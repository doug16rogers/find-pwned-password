#!/bin/bash

while read -s -p "Password to check (Ctrl-C to quit): " pass; do
    start=$SECONDS
    hash=$(echo -n "$pass" | sha1sum | cut -f1 '-d ' | tr [:lower:] [:upper:])
    pass=""
    echo -e "\nLooking for hash $hash."
    echo -n "... "
    result=$(grep -m1 "^$hash" pwned-passwords-2.0.txt | tr -d ' \r\n')
    if [[ -z "$result" ]]; then
        result="<not-found>"
    fi
    stop=$SECONDS
    echo "$result ($[stop-start]s)"
done
