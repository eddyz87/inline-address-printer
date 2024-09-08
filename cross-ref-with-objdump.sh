#!/bin/bash

# Cross check inline_address_printer with objdump:
# - for a specific function in a binary file get a list of
#   callsite addresses;
# - do objdump -S around each address and check if function name
#   is mentioned in the resulting snippet
#   (hoping that -S parameter would fetch relevant C lines,
#    not always true)

dir=$(realpath $(dirname $0))
printer=$dir/inline_address_printer

obj=$1
func=$2
if [[ "$obj" == "" || "$func" == "" ]]; then
    echo "Usage:"
    echo "  $0 <object-file> <function-name>"
    exit 1
fi

addrs=$(${printer} --no-stats --func $2 $obj | awk '{ print $2; }' | sed 's/0x//')

for addr in $addrs
do
    echo "-------------- $addr --------------"
    start=$((0x$addr - 0x20))
    stop=$((0x$addr + 0x20))
    out="$(objdump -Sd --no-show-raw-insn	\
            --start-address $start		\
            --stop-address  $stop		\
            $obj)"
    echo "$out" | grep -E --color -e $addr:'|'$func'|$'
    if !(echo "$out" | grep -q "$func"); then
        echo ""
        echo "!!! func not found !!!"
    fi
    echo ""
done
