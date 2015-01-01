#!/usr/bin/bash
perl -lne 'print $& if /(\d+\.){3}\d+/' "$1" > "$2"
tshark -r "$3" -n -T fields -E separator=, -e 'ip.src' > "$4"

