#!/bin/sh
make EXTRA_CFLAGS="-pg -static"
time ./http
gprof ./http gmon.out -p
