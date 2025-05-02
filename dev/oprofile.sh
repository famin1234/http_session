#!/bin/sh
make EXTRA_CFLAGS="-static"
opcontrol --deinit
modprobe oprofile timer=1
opcontrol --reset
opcontrol --start --no-vmlinux
time ./http
opcontrol --dump
opcontrol --shutdown
opreport -l ./http

