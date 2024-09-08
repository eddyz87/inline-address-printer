LDFLAGS=-ldw -lelf
CFLAGS=-Wall -g

# This generates compile_commands.json for language server
BEAR:=$(shell (which bear 2>&1 >/dev/null) && echo "bear --")

default: inline_address_printer

inline_address_printer: main.c
	$(BEAR) gcc $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm -f inline_address_printer
