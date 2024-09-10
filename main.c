#include <argp.h>
#include <dwarf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libelf.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <elfutils/libdw.h>
#include <elfutils/libdwfl.h>
#include <elfutils/known-dwarf.h>

struct ctx
{
  char *filter_func;
  char *filter_file;
  char *filter_cu;
  char *elf_file_name;
  bool stats_only;
  bool no_stats;
  bool show_dwarf_details;

  Dwarf *dbg;
  Elf64_Addr *section_starts;
  int sections_num;
  int frame_base_reg;

  long all_formals_all_simple_callsites;
  long all_formals_ccmatch_callsites;
  long all_formals_callsites;
  long total_callsites;
  long simple_formals;
  long total_formals;
  long known_formals;
};

static void report(struct ctx *ctx, const char *fmt, ...)
{
  va_list ap;

  if (ctx->stats_only)
    return;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
}

static bool is_suffix(const char *suffix, const char *str)
{
  int suffix_len = strlen(suffix);
  int str_len = strlen(str);

  if (str_len < suffix_len)
    return false;
  return strcmp(suffix, str + str_len - suffix_len) == 0;
}

static uint64_t section_relative_addr(struct ctx *ctx, uint64_t addr)
{
  for (int i = 1; i < ctx->sections_num; ++i)
    if (ctx->section_starts[i-1] <= addr &&
        addr < ctx->section_starts[i])
      return addr - ctx->section_starts[i-1];
  return addr - ctx->section_starts[ctx->sections_num - 1];
}

enum { OPN_UNKNOWN = 0, OPN_ZERO = 1, OPN_ONE = 2, OPN_TWO = 3 };

static const char *dw_op_names[];
static const char dw_op_num_params[];

static void print_expr(Dwarf_Op *exprs, size_t exprlen)
{
  for (size_t i = 0; i < exprlen; ++i) {
    Dwarf_Op *expr = &exprs[i];
    const char *name = dw_op_names[expr->atom];
    if (i)
      printf("; ");
    if (name)
      printf("%s", name);
    else
      printf("0x%02x", expr->atom);
    switch (dw_op_num_params[expr->atom]) {
    case OPN_ZERO:
      break;
    case OPN_ONE:
      printf(" 0x%lx", expr->number);
      break;
    default:
      printf(" 0x%lx", expr->number);
      printf(" 0x%lx", expr->number2);
      break;
    }
  }
}

/* See: System V Application Binary Interface
 *      AMD64 Architecture Processor Supplement
 *      Version 1.0
 * Figure 3.36: DWARF Register Number Mapping
 */
static char *dwarf_reg_to_x86(int num)
{
  switch (num) {
  case 0:  return "rax";
  case 1:  return "rdx";
  case 2:  return "rcx";
  case 3:  return "rbx";
  case 4:  return "rsi";
  case 5:  return "rdi";
  case 6:  return "rbp";
  case 7:  return "rsp";
  case 8:  return "r8";
  case 9:  return "r9";
  case 10: return "r10";
  case 11: return "r11";
  case 12: return "r12";
  case 13: return "r13";
  case 14: return "r14";
  case 15: return "r15";
  }
  return NULL;
}

static int x86_cc_param_reg(int num)
{
  switch (num) {
  case 1: return DW_OP_reg5; // rdi
  case 2: return DW_OP_reg4; // rsi
  case 3: return DW_OP_reg1; // rdx
  case 4: return DW_OP_reg2; // rcx
  case 5: return DW_OP_reg8; // r8
  case 6: return DW_OP_reg9; // r9
  default:
    return 0;
  }
}

static bool decode_expr(struct ctx *ctx, int frame_base_reg, Dwarf_Op *expr)
{
  uint8_t atom = expr->atom;
  char *reg_name;

  switch (atom) {
  case DW_OP_reg0  ... DW_OP_reg15:
    report(ctx, "%s", dwarf_reg_to_x86(atom - DW_OP_reg0));
    return true;
  case DW_OP_breg0 ... DW_OP_breg15:
    report(ctx, "%s+%ld", dwarf_reg_to_x86(atom - DW_OP_breg0), (long)expr->number);
    return true;
  case DW_OP_lit0  ... DW_OP_lit31:
    report(ctx, "%d", atom - DW_OP_lit0);
    return true;
  case DW_OP_fbreg:
    reg_name = dwarf_reg_to_x86(frame_base_reg);
    if (!reg_name)
      return false;
    report(ctx, "%s+%ld", reg_name, (long)expr->number);
    return true;
  case DW_OP_const1u:
  case DW_OP_const2u:
  case DW_OP_const4u:
  case DW_OP_const8u:
  case DW_OP_constu:
    report(ctx, "%ld", (long)expr->number);
    return true;
  case DW_OP_const1s:
  case DW_OP_const2s:
  case DW_OP_const4s:
  case DW_OP_const8s:
  case DW_OP_consts:
  case DW_OP_addr:
    report(ctx, "%lu", expr->number);
    return true;
  }
  return false;
}

static bool find_location(Dwarf_Die *die, uint64_t addr, Dwarf_Op **expr, size_t *exprlen)
{
  Dwarf_Addr startp, endp, basep;
  Dwarf_Attribute attr;
  ptrdiff_t off;

  if (dwarf_attr(die, DW_AT_location, &attr)) {
    for (off = dwarf_getlocations(&attr, 0, &basep, &startp, &endp, expr, exprlen);
         off > 0;
         off = dwarf_getlocations(&attr, off, &basep, &startp, &endp, expr, exprlen)) {
      if (addr < startp || endp <= addr)
        continue;
      return true;
    }
  }
  return false;
}

enum const_kind {
  CK_STRING,
  CK_SIGNED,
  CK_UNSIGNED,
  CK_ADDRESS,
  CK_STRANGE,
};

struct const_attr_value {
  enum const_kind kind;
  union {
      Dwarf_Sword sword;
      Dwarf_Word  word;
      Dwarf_Addr  addr;
      const char *string;
  };
};

static bool get_const_value(Dwarf_Die *die, struct const_attr_value *val) {
  Dwarf_Attribute attr;

  if (!dwarf_attr(die, DW_AT_const_value, &attr))
    return false;

  if ((val->string = dwarf_formstring(&attr))) {
    val->kind = CK_STRING;
  } else if (dwarf_formudata(&attr, &val->word) == 0) {
    val->kind = CK_UNSIGNED;
  } else if (dwarf_formsdata(&attr, &val->sword) == 0) {
    val->kind = CK_SIGNED;
  } else if (dwarf_formaddr(&attr, &val->addr) == 0) {
    val->kind = CK_ADDRESS;
  } else {
    val->kind = CK_STRANGE;
    fprintf(stderr, "formal die <%p> unexpected const form\n", (void *)dwarf_dieoffset(die));
  }
  return true;
}

static void print_const_value(struct ctx *ctx, struct const_attr_value *val)
{
  switch (val->kind) {
  case CK_STRING:
    report(ctx, " \"%s\"", val->string);
    break;
  case CK_UNSIGNED:
    report(ctx, " %lu", val->word);
    break;
  case CK_SIGNED:
    report(ctx, " %ld", val->sword);
    break;
  case CK_ADDRESS:
    report(ctx, " %8p", (void*)val->addr);
    break;
  default:
    report(ctx, " <const>");
    break;
  }
}

#define MAX_FORMALS 64

struct formals {
  Dwarf_Off offsets[MAX_FORMALS];
  const char *names[MAX_FORMALS];
  int count;
};

static void collect_formals(Dwarf_Die *die, struct formals *formals)
{
  Dwarf_Die child;
  int err;

  for (err = dwarf_child(die, &child);
       err == 0;
       err = dwarf_siblingof(&child, &child)) {
    if (dwarf_tag(&child) != DW_TAG_formal_parameter)
      continue;
    if (formals->count == MAX_FORMALS) {
      fprintf(stderr, "too many formals in die %p\n", (void *)dwarf_dieoffset(die));
      break;
    }
    formals->offsets[formals->count] = dwarf_dieoffset(&child);
    formals->names[formals->count] = dwarf_diename(&child);
    ++formals->count;
  }
}

static void show_formals_dwarf(struct ctx *ctx, Dwarf_Die *die, Dwarf_Die *origin, Dwarf_Addr startp)
{
  Dwarf_Attribute attr;
  Dwarf_Die formal;
  Dwarf_Op *expr;
  const char *name;
  unsigned int tag;
  size_t exprlen;
  int padding;
  int err;

  report(ctx, "  die %p origin %p\n",
         (void *)dwarf_dieoffset(die), (void *)dwarf_dieoffset(origin));
  for (err = dwarf_child(die, &formal);
       err == 0;
       err = dwarf_siblingof(&formal, &formal)) {
    tag = dwarf_tag(&formal);
    if (tag != DW_TAG_formal_parameter)
      continue;
    name = dwarf_diename(&formal);
    padding = 10 - strlen(name);
    padding = padding < 0 ? 0 : padding;
    if (dwarf_attr(&formal, DW_AT_const_value, &attr)) {
      report(ctx, "    formal '%s'%*s const\n", name, padding, "");
    } else if (find_location(&formal, startp, &expr, &exprlen)) {
      printf("    formal '%s'%*s location (", name, padding, "");
      print_expr(expr, exprlen);
      printf(")\n");
    } else {
      report(ctx, "    formal '%s'%*s location unknown\n", name, padding, "");
    }
  }
}

static void show_die(struct ctx *ctx, Dwarf_Die *die)
{
  Dwarf_Addr startp, endp, basep, sec_rel_startp;
  Dwarf_Attribute attr;
  Dwarf_Die origin;
  struct formals callsite_formals = {};
  struct formals origin_formals = {};
  const char *name, *decl_file;
  int num_simple_formals = 0;
  int num_known_formals = 0;
  int num_formals = 0;
  int num_ccmatch = 0;
  unsigned int tag;
  ptrdiff_t off;
  int padding;

  tag = dwarf_tag(die);
  if (tag != DW_TAG_inlined_subroutine)
    return;

  if (dwarf_attr(die, DW_AT_abstract_origin, &attr) == NULL)
    return;

  if (dwarf_formref_die(&attr, &origin) == NULL)
    return;

  name = dwarf_diename(&origin);
  decl_file = dwarf_decl_file(&origin);

  if (ctx->filter_func &&
      (!name || strcmp(name, ctx->filter_func) != 0))
    return;

  if (ctx->filter_file &&
      (!decl_file || !is_suffix(ctx->filter_file, decl_file)))
    return;

  ctx->total_callsites++;

  off = dwarf_ranges(die, 0, &basep, &startp, &endp);
  if (off < 0) {
    fprintf(stderr, "no low/ranges for die <%p>\n", (void *)dwarf_dieoffset(die));
    return;
  }

  collect_formals(&origin, &origin_formals);
  collect_formals(die, &callsite_formals);
  sec_rel_startp = section_relative_addr(ctx, startp);
  padding = 80 - strlen(decl_file) - strlen(name);
  padding = padding < 0 ? 0 : padding;
  report(ctx, "%s:%s%*s %8p", decl_file, name, padding, "", (void *)sec_rel_startp);
  for (int i = 0; i < origin_formals.count; ++i) {
    Dwarf_Die formal = {};
    Dwarf_Op *exprs;
    struct const_attr_value value;
    bool found = false;
    size_t exprlen;

    for (int j = 0; j < callsite_formals.count; ++j) {
      if (strcmp(origin_formals.names[i], callsite_formals.names[j]) == 0) {
        dwarf_offdie(ctx->dbg, callsite_formals.offsets[j], &formal);
        found = true;
        break;
      }
    }

    if (found)
      ++num_formals;

    if (!found) {
      report(ctx, " <missing>");
    } else if (get_const_value(&formal, &value)) {
      if (value.kind != CK_STRANGE)
        ++num_simple_formals;
      ++num_known_formals;
      print_const_value(ctx, &value);
    } else if (find_location(&formal, startp, &exprs, &exprlen)) {
      if (exprlen > 0 && exprs[exprlen - 1].atom == DW_OP_stack_value)
        --exprlen;
      report(ctx, " ");
      if (exprlen == 1 && decode_expr(ctx, ctx->frame_base_reg, &exprs[0]))
        ++num_simple_formals;
      else
        report(ctx, "<complex_loc>");
      if (exprlen == 1 && exprs[0].atom == x86_cc_param_reg(num_formals))
        ++num_ccmatch;
      ++num_known_formals;
    } else if (dwarf_attr(&formal, DW_AT_location, &attr)) {
      report(ctx, " <no_entry_loc>");
    } else {
      report(ctx, " <no_loc>");
    }
  }
  report(ctx, "\n");

  ctx->total_formals += num_formals;
  ctx->known_formals += num_known_formals;
  ctx->simple_formals += num_simple_formals;
  if (num_formals == origin_formals.count &&
      num_formals == num_simple_formals)
    ++ctx->all_formals_all_simple_callsites;
  if (num_formals == origin_formals.count &&
      num_formals == num_ccmatch)
    ++ctx->all_formals_ccmatch_callsites;
  if (num_formals == origin_formals.count &&
      num_formals == num_known_formals)
    ++ctx->all_formals_callsites;

  if (ctx->show_dwarf_details)
    show_formals_dwarf(ctx, die, &origin, startp);
}

static int get_frame_base_reg(Dwarf_Die *die)
{
  Dwarf_Attribute frame_base;
  Dwarf_Op *exprs;
  size_t exprlen;

  if (dwarf_attr(die, DW_AT_frame_base, &frame_base) &&
      dwarf_getlocation(&frame_base, &exprs, &exprlen) &&
      exprlen == 1 &&
      exprs[0].atom >= DW_OP_reg0 &&
      exprs[0].atom <= DW_OP_reg15)
    return exprs[0].atom - DW_OP_reg0;

  return 0;
}

static void traverse(struct ctx *ctx, Dwarf_Die *die)
{
  int err, old_base, base_reg;
  Dwarf_Die child;

  show_die(ctx, die);
  if (!dwarf_haschildren(die))
    return;
  for (err = dwarf_child(die, &child);
       err == 0;
       err = dwarf_siblingof(&child, &child)) {
    old_base = ctx->frame_base_reg;
    base_reg = get_frame_base_reg(&child);
    if (dwarf_tag(&child) == DW_TAG_subprogram)
      ctx->frame_base_reg = base_reg;
    else if (dwarf_tag(&child) == DW_TAG_inlined_subroutine && base_reg)
      ctx->frame_base_reg = base_reg;
    else
      ctx->frame_base_reg = 0;

    traverse(ctx, &child);

    ctx->frame_base_reg = old_base;
  }
}

static int cmp_elf64_addr(const void *_a, const void *_b)
{
  const Elf64_Addr *a = _a, *b = _b;

  if (*a < *b)
    return -1;
  if (*a > *b)
    return 1;
  return 0;
}

static void report_dwfl_err(const char *msg)
{
  fprintf(stderr, "%s: %s\n", msg, dwfl_errmsg(dwfl_errno()));
}

static void report_elf_err(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, elf_errmsg(elf_errno()));
}

static int process_mod(Dwfl_Module *mod, struct ctx *ctx)
{
  GElf_Ehdr ehdr_mem;
  Dwarf_Addr dwbias;
  GElf_Addr dwflbias;
  size_t sections_num;
  Elf64_Addr *section_starts;
  Dwarf *dbg;
  Elf *elf;
  int err;

  elf = dwfl_module_getelf(mod, &dwflbias);
  if (!elf) {
    report_dwfl_err("dwfl_module_getelf() failed");
    return -EINVAL;
  }

  if (gelf_getehdr(elf, &ehdr_mem) == NULL) {
    report_elf_err("gelf_getehdr() failed");
    return -EINVAL;
  }

  dbg = dwfl_module_getdwarf(mod, &dwbias);
  if (!dbg) {
    report_dwfl_err("dwfl_module_getdwarf() failed");
    return -EINVAL;
  }

  err = elf_getshdrnum(elf, &sections_num);
  if (err) {
    report_elf_err("elf_getshdrnum() failed");
    return -EINVAL;
  }

  section_starts = calloc(sizeof(*section_starts), sections_num);
  if (!section_starts) {
    printf("calloc() failed\n");
    return -ENOMEM;
  }

  if (ehdr_mem.e_type == ET_REL) {
    for (size_t i = 0; i < sections_num; ++i) {
      Elf_Scn *sec = elf_getscn(elf, i);
      if (!sec) {
        report_elf_err("elf_getscn() failed");
        err = -EINVAL;
        goto out;
      }
      Elf64_Shdr *shdr = elf64_getshdr(sec);
      if (!shdr) {
        report_elf_err("elf64_getshdr failed");
        err = -EINVAL;
        goto out;
      }
      section_starts[i] = shdr->sh_addr;
    }
    qsort(section_starts, sections_num, sizeof(*section_starts), cmp_elf64_addr);
  }

  ctx->dbg = dbg;
  ctx->section_starts = section_starts;
  ctx->sections_num = sections_num;

  Dwarf_Off next_off = 0;
  Dwarf_Off off = 0;
  Dwarf_Die cu;
  size_t hsize;

  report(ctx, "# %-79s %-18s parameters...\n", "file:func", "callsite");
  while (dwarf_nextcu(dbg, off, &next_off, &hsize,
                      NULL, NULL, NULL) == 0) {

    if (dwarf_offdie(dbg, off + hsize, &cu) != NULL) {
      if (ctx->filter_cu && !is_suffix(ctx->filter_cu, dwarf_diename(&cu)))
        goto next_cu;
      traverse(ctx, &cu);
    }

  next_cu:
    off = next_off;
  }

 out:
  free(section_starts);
  return err;
}

enum {
  OPT_STATS_ONLY = 0x100,
  OPT_NO_STATS,
  OPT_FILTER_FUNC,
  OPT_FILTER_FILE,
  OPT_FILTER_CU,
  OPT_DWARF_DETAILS,
};

static struct argp_option opts[] = {
  { "stats-only", OPT_STATS_ONLY, 0, 0,
  "Print stats about callsites and formals, don't print actual DIEs" },
  { "no-stats", OPT_NO_STATS, 0, 0,
  "Don't print stats" },
  { "func", OPT_FILTER_FUNC, "<function>", 0,
  "Filter callsites by called function name" },
  { "file", OPT_FILTER_FILE, "<file>", 0,
  "Filter callsites by called function file of origin" },
  { "cu", OPT_FILTER_CU, "<name>", 0,
  "Filter callsites by calling file name" },
  { "dwarf-details", OPT_DWARF_DETAILS, 0, 0,
  "Print DIE offset and DWARF expressions for formal parameters" },
  { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
  struct ctx *ctx = state->input;

  switch (key) {
  case OPT_STATS_ONLY:
    ctx->stats_only = true;
    ctx->show_dwarf_details = false;
    break;
  case OPT_NO_STATS:
    ctx->no_stats = true;
    break;
  case OPT_FILTER_FUNC:
    ctx->filter_func = arg;
    break;
  case OPT_FILTER_FILE:
    ctx->filter_file = arg;
    break;
  case OPT_FILTER_CU:
    ctx->filter_cu = arg;
    break;
  case OPT_DWARF_DETAILS:
    ctx->show_dwarf_details = true;
    break;
  case ARGP_KEY_ARG:
    ctx->elf_file_name = arg;
    break;
  case ARGP_KEY_END:
    if (state->arg_num != 1)
      argp_state_help(state, stderr, ARGP_HELP_USAGE | ARGP_HELP_EXIT_ERR);
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {
  opts, parse_opt, "<elf file name>",
  "Print callsite addresses for inlined function calls."
};

int main (int argc, char *argv[])
{
  struct ctx ctx = {};
  Dwfl_Module *mod;
  Dwfl *dwfl;
  char *file;
  int fd;

  argp_parse(&argp, argc, argv, 0, NULL, &ctx);
  file = ctx.elf_file_name;

  static const Dwfl_Callbacks callbacks = {
    .section_address = dwfl_offline_section_address,
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .find_elf = dwfl_build_id_find_elf,
  };

  fd = open(file, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "open('%s') failed: %s\n", file, strerror(errno));
    return 1;
  }

  dwfl = dwfl_begin(&callbacks);
  if (!dwfl) {
    report_dwfl_err("dwfl_begin() failed");
    close(fd);
    return 1;
  }

  mod = dwfl_report_offline(dwfl, file, file, dup(fd));
  if (mod == NULL) {
    report_dwfl_err("dwfl_report_offline() failed");
    dwfl_end(dwfl);
    close(fd);
    return 1;
  }

  dwfl_report_end(dwfl, NULL, NULL);
  process_mod(mod, &ctx);
  dwfl_end(dwfl);
  close(fd);

  if (!ctx.no_stats) {
    if (ctx.total_callsites > 0)
          printf("\n");

    printf("# Total inlined callsites                             : %6ld\n", ctx.total_callsites);
    printf("#   with all formals present                          : %6ld (%2.f%%)\n",
           ctx.all_formals_callsites,
           (double)ctx.all_formals_callsites / ctx.total_callsites * 100);
    printf("#   with all formals present and in simple locations  : %6ld (%2.f%%)\n",
           ctx.all_formals_all_simple_callsites,
           (double)ctx.all_formals_all_simple_callsites / ctx.total_callsites * 100);
    printf("#   with all formals as in calling convention         : %6ld (%2.f%%)\n",
           ctx.all_formals_ccmatch_callsites,
           (double)ctx.all_formals_ccmatch_callsites / ctx.total_callsites * 100);

    printf("#\n");
    printf("# Total formals                                       : %6ld\n", ctx.total_formals);
    printf("#   with location                                     : %6ld (%2.f%%)\n",
           ctx.known_formals,
           (double)ctx.known_formals / ctx.total_formals * 100);
    printf("#   with simple location                              : %6ld (%2.f%%)\n",
           ctx.simple_formals,
           (double)ctx.simple_formals / ctx.total_formals * 100);
    printf("\n");
  }
  return 0;
}

static const char *dw_op_names[] = {
#define DWARF_ONE_KNOWN_DW_OP(name, enum_val) [enum_val] = #name,
DWARF_ALL_KNOWN_DW_OP
#undef DWARF_ONE_KNOWN_DW_OP
};

static const char dw_op_num_params[] = {
  [DW_OP_addr]			= OPN_ONE,
  [DW_OP_deref]			= OPN_ZERO,
  [DW_OP_const1u]		= OPN_ONE,
  [DW_OP_const1s]		= OPN_ONE,
  [DW_OP_const2u]		= OPN_ONE,
  [DW_OP_const2s]		= OPN_ONE,
  [DW_OP_const4u]		= OPN_ONE,
  [DW_OP_const4s]		= OPN_ONE,
  [DW_OP_const8u]		= OPN_ONE,
  [DW_OP_const8s]		= OPN_ONE,
  [DW_OP_constu]		= OPN_ONE,
  [DW_OP_consts]		= OPN_ONE,
  [DW_OP_dup]			= OPN_ZERO,
  [DW_OP_drop]			= OPN_ZERO,
  [DW_OP_over]			= OPN_ZERO,
  [DW_OP_pick]			= OPN_ONE,
  [DW_OP_swap]			= OPN_ZERO,
  [DW_OP_rot]			= OPN_ZERO,
  [DW_OP_xderef]		= OPN_ZERO,
  [DW_OP_abs]			= OPN_ZERO,
  [DW_OP_and]			= OPN_ZERO,
  [DW_OP_div]			= OPN_ZERO,
  [DW_OP_minus]			= OPN_ZERO,
  [DW_OP_mod]			= OPN_ZERO,
  [DW_OP_mul]			= OPN_ZERO,
  [DW_OP_neg]			= OPN_ZERO,
  [DW_OP_not]			= OPN_ZERO,
  [DW_OP_or]			= OPN_ZERO,
  [DW_OP_plus]			= OPN_ZERO,
  [DW_OP_plus_uconst]		= OPN_ONE,
  [DW_OP_shl]			= OPN_ZERO,
  [DW_OP_shr]			= OPN_ZERO,
  [DW_OP_shra]			= OPN_ZERO,
  [DW_OP_xor]			= OPN_ZERO,
  [DW_OP_bra]			= OPN_ONE,
  [DW_OP_eq]			= OPN_ZERO,
  [DW_OP_ge]			= OPN_ZERO,
  [DW_OP_gt]			= OPN_ZERO,
  [DW_OP_le]			= OPN_ZERO,
  [DW_OP_lt]			= OPN_ZERO,
  [DW_OP_ne]			= OPN_ZERO,
  [DW_OP_skip]			= OPN_ONE,
  [DW_OP_lit0] 			= OPN_ZERO,
  [DW_OP_lit1] 			= OPN_ZERO,
  [DW_OP_lit2] 			= OPN_ZERO,
  [DW_OP_lit3] 			= OPN_ZERO,
  [DW_OP_lit4] 			= OPN_ZERO,
  [DW_OP_lit5] 			= OPN_ZERO,
  [DW_OP_lit6] 			= OPN_ZERO,
  [DW_OP_lit7] 			= OPN_ZERO,
  [DW_OP_lit8] 			= OPN_ZERO,
  [DW_OP_lit9] 			= OPN_ZERO,
  [DW_OP_lit10] 		= OPN_ZERO,
  [DW_OP_lit11] 		= OPN_ZERO,
  [DW_OP_lit12] 		= OPN_ZERO,
  [DW_OP_lit13] 		= OPN_ZERO,
  [DW_OP_lit14] 		= OPN_ZERO,
  [DW_OP_lit15] 		= OPN_ZERO,
  [DW_OP_lit16] 		= OPN_ZERO,
  [DW_OP_lit17] 		= OPN_ZERO,
  [DW_OP_lit18] 		= OPN_ZERO,
  [DW_OP_lit19] 		= OPN_ZERO,
  [DW_OP_lit20] 		= OPN_ZERO,
  [DW_OP_lit21] 		= OPN_ZERO,
  [DW_OP_lit22] 		= OPN_ZERO,
  [DW_OP_lit23] 		= OPN_ZERO,
  [DW_OP_lit24] 		= OPN_ZERO,
  [DW_OP_lit25] 		= OPN_ZERO,
  [DW_OP_lit26] 		= OPN_ZERO,
  [DW_OP_lit27] 		= OPN_ZERO,
  [DW_OP_lit28] 		= OPN_ZERO,
  [DW_OP_lit29] 		= OPN_ZERO,
  [DW_OP_lit30] 		= OPN_ZERO,
  [DW_OP_lit31] 		= OPN_ZERO,
  [DW_OP_reg0] 			= OPN_ZERO,
  [DW_OP_reg1]  		= OPN_ZERO,
  [DW_OP_reg2]  		= OPN_ZERO,
  [DW_OP_reg3]  		= OPN_ZERO,
  [DW_OP_reg4]  		= OPN_ZERO,
  [DW_OP_reg5]  		= OPN_ZERO,
  [DW_OP_reg6]  		= OPN_ZERO,
  [DW_OP_reg7]  		= OPN_ZERO,
  [DW_OP_reg8]  		= OPN_ZERO,
  [DW_OP_reg9]  		= OPN_ZERO,
  [DW_OP_reg10]  		= OPN_ZERO,
  [DW_OP_reg11]  		= OPN_ZERO,
  [DW_OP_reg12]  		= OPN_ZERO,
  [DW_OP_reg13]  		= OPN_ZERO,
  [DW_OP_reg14]  		= OPN_ZERO,
  [DW_OP_reg15]  		= OPN_ZERO,
  [DW_OP_reg16]  		= OPN_ZERO,
  [DW_OP_reg17]  		= OPN_ZERO,
  [DW_OP_reg18]  		= OPN_ZERO,
  [DW_OP_reg19]  		= OPN_ZERO,
  [DW_OP_reg20]  		= OPN_ZERO,
  [DW_OP_reg21]  		= OPN_ZERO,
  [DW_OP_reg22]  		= OPN_ZERO,
  [DW_OP_reg23]  		= OPN_ZERO,
  [DW_OP_reg24]  		= OPN_ZERO,
  [DW_OP_reg25]  		= OPN_ZERO,
  [DW_OP_reg26]  		= OPN_ZERO,
  [DW_OP_reg27]  		= OPN_ZERO,
  [DW_OP_reg28]  		= OPN_ZERO,
  [DW_OP_reg29]  		= OPN_ZERO,
  [DW_OP_reg30]  		= OPN_ZERO,
  [DW_OP_reg31]  		= OPN_ZERO,
  [DW_OP_breg0]			= OPN_ONE,
  [DW_OP_breg1]			= OPN_ONE,
  [DW_OP_breg2]			= OPN_ONE,
  [DW_OP_breg3]			= OPN_ONE,
  [DW_OP_breg4]			= OPN_ONE,
  [DW_OP_breg5]			= OPN_ONE,
  [DW_OP_breg6]			= OPN_ONE,
  [DW_OP_breg7]			= OPN_ONE,
  [DW_OP_breg8]			= OPN_ONE,
  [DW_OP_breg9]			= OPN_ONE,
  [DW_OP_breg10]		= OPN_ONE,
  [DW_OP_breg11]		= OPN_ONE,
  [DW_OP_breg12]		= OPN_ONE,
  [DW_OP_breg13]		= OPN_ONE,
  [DW_OP_breg14]		= OPN_ONE,
  [DW_OP_breg15]		= OPN_ONE,
  [DW_OP_breg16]		= OPN_ONE,
  [DW_OP_breg17]		= OPN_ONE,
  [DW_OP_breg18]		= OPN_ONE,
  [DW_OP_breg19]		= OPN_ONE,
  [DW_OP_breg20]		= OPN_ONE,
  [DW_OP_breg21]		= OPN_ONE,
  [DW_OP_breg22]		= OPN_ONE,
  [DW_OP_breg23]		= OPN_ONE,
  [DW_OP_breg24]		= OPN_ONE,
  [DW_OP_breg25]		= OPN_ONE,
  [DW_OP_breg26]		= OPN_ONE,
  [DW_OP_breg27]		= OPN_ONE,
  [DW_OP_breg28]		= OPN_ONE,
  [DW_OP_breg29]		= OPN_ONE,
  [DW_OP_breg30]		= OPN_ONE,
  [DW_OP_breg31] 		= OPN_ONE,
  [DW_OP_regx] 			= OPN_ONE,
  [DW_OP_fbreg] 		= OPN_ONE,
  [DW_OP_bregx] 		= OPN_TWO,
  [DW_OP_piece] 		= OPN_ONE,
  [DW_OP_deref_size] 		= OPN_ONE,
  [DW_OP_xderef_size] 		= OPN_ONE,
  [DW_OP_nop] 			= OPN_ZERO,
  [DW_OP_push_object_address]	= OPN_ZERO,
  [DW_OP_call2]			= OPN_ONE,
  [DW_OP_call4]			= OPN_ONE,
  [DW_OP_call_ref]		= OPN_ONE,
  [DW_OP_form_tls_address]	= OPN_ZERO,
  [DW_OP_call_frame_cfa] 	= OPN_ZERO,
  [DW_OP_bit_piece]		= OPN_TWO,
  [DW_OP_implicit_value] 	= OPN_TWO,
  [DW_OP_stack_value] 		= OPN_ZERO,
  [DW_OP_GNU_implicit_pointer] 	= OPN_TWO,
  [DW_OP_addrx]			= OPN_ONE,
  [DW_OP_constx]		= OPN_ONE,
  [DW_OP_GNU_entry_value]	= OPN_TWO,
  [DW_OP_GNU_regval_type]   	= OPN_TWO,
  [DW_OP_GNU_deref_type]    	= OPN_TWO,
  [DW_OP_xderef_type]   	= OPN_TWO,
  [DW_OP_GNU_convert]      	= OPN_ONE,
  [DW_OP_GNU_reinterpret]  	= OPN_ONE,
  [0xff]			= OPN_UNKNOWN,
};
