# Description

Print callsite addresses for inlined function calls, understands the
following command line arguments:

```
      --cu=<name>            Filter callsites by calling file name
      --dwarf-details        Print DIE offset and DWARF expressions for formal
                             parameters
      --file=<file>          Filter callsites by called function file of origin
                            
      --func=<function>      Filter callsites by called function name
      --no-stats             Don't print stats
      --stats-only           Print stats about callsites and formals, don't
                             print actual DIEs
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

Example usage #1:

```
$ ./inline_address_printer ~/work/bpf-next/vmlinux --func subprog_name
# file:func                                                                       callsite           parameters...
/home/eddy/work/bpf-next/kernel/bpf/verifier.c:subprog_name                       0xffffffff8126ee3c rbx r12
/home/eddy/work/bpf-next/kernel/bpf/verifier.c:subprog_name                       0xffffffff8126d6f5 r14 rbp
/home/eddy/work/bpf-next/kernel/bpf/verifier.c:subprog_name                       0xffffffff81274205 rbx r12

# Total inlined callsites                             : 3
#   with all formals present                          : 3 (100%)
#   with all formals present and in simple locations  : 3 (100%)
#
# Total formals                                       : 6
#   with location                                     : 6 (100%)
#   with simple location                              : 6 (100%)
```

The above prints all locations recorded in DWARF, where function
`subprog_name()` was inlined.

Example usage #2:

```
$ ./inline_address_printer ~/work/bpf-next/vmlinux --stats-only

# Total inlined callsites                             : 345592
#   with all formals present                          : 240655 (70%)
#   with all formals present and in simple locations  : 231864 (67%)
#
# Total formals                                       : 457151
#   with location                                     : 436205 (95%)
#   with simple location                              : 425309 (93%)
```

Get some statistics about inlined functions in the binary file:
- how many inlined function callsites recorded in DWARF;
- how many such callsites have enough `DW_TAG_formal_parameter` tags
  to describe all formal parameters;
- how many such callsites also have all `DW_TAG_formal_parameter`
  with `DW_AT_location` describing a simple location;
- how many `DW_TAG_formal_parameter` DIEs are children of
  `DW_TAG_inlined_subroutine` DIEs;
- how many of such `DW_TAG_formal_parameter` DIEs describe easily
  accessible manner to read the formal parameter and callsite address.

Where "simple location" means that actual value of the formal is
available as:
- a register;
- a register + constant value;
- a constant value;

# Build instructions

Just do `make` in the project directory. Depends on `libelf` and
`libdw`, on Fedora these are available as the following packages:
- `elfutils-libelf`
- `elfutils-libs`
- `elfutils-devel`
