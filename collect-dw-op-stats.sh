#!/bin/bash

# Print shapes and frequencies of DWARF expressions

dir=$(realpath $(dirname $0))
printer=$dir/inline_address_printer

obj=$1
if [[ "$obj" == "" ]]; then
    echo "Usage:"
    echo "  $0 <object-file>"
    exit 1
fi

$printer --dwarf-details \
    $obj \
    | grep "formal" \
    | sed -E "s/ +/ /g" \
    | grep -P "formal '[^']*' (loc|const)" \
    | sed -E "s/formal '[^']*'/formalX/" \
    | sed -E 's/0x[0-9a-f]+/X/g' \
    | sed -E 's/reg[0-9]+/regX/g' \
    | sed -E 's/lit[0-9]+/litX/g' \
    | sort \
    | uniq -c \
    | sort -k1n
