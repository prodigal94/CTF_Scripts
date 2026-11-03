#!/bin/bash

TARGET="192.168.1.0/24"
MAX_JOBS=10

discover() {
    # to fill: [authorized host discovery command and output handling]
    :
    for i in {1..255}; do
        nmap -sn "$TARGET"
        awk -F'[./]' -v n="$i" '{
            printf "%s.%s.%d.%s/%s\n", $1, $2, $i, $4, $5
        }' <<< "$TARGET"
    done
}

scan_host() {
    local host="$1"

    # to fill: [individual follow-up scan command]
    :
    nmap -sCV -O $host
}

while IFS= read -r host; do
    [[ -z "$host" ]] && continue

    while (( $(jobs -rp | wc -l) >= MAX_JOBS )); do
        wait -n
    done

    scan_host "$host" &
done < <(discover)

wait
echo "All jobs completed."