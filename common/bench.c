#include "bench.h"

#include <inttypes.h>
#include <stdio.h>
#include <time.h>

uint64_t bench_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

void bench_log(const char *label, uint64_t value, const char *unit)
{
    printf("BENCH,%s,%" PRIu64 ",%s\n", label, value, unit);
}
