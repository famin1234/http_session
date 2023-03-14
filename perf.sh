#!/bin/sh
make EXTRA_CFLAGS="-static"
perf stat -e task-clock -e cycles -e context-switches -e migrations -e instructions -e page-faults,cache-misses,L1-dcache-load-misses,L1-dcache-loads,L1-dcache-stores,L1-icache-load-misses,branch-load-misses,branch-loads,dTLB-load-misses,dTLB-loads,dTLB-store-misses,dTLB-stores,iTLB-load-misses,iTLB-loads ./http
