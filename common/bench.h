/* Timing and logging helpers for measurements. Owner: Shalom.
 * The function list is the shared contract (CLAUDE.md section 8). */
#ifndef QD_BENCH_H
#define QD_BENCH_H

#include <stdint.h>

/* Current time in nanoseconds from a clock that never jumps backwards
 * (CLOCK_MONOTONIC). Only differences between two calls are meaningful. */
uint64_t bench_now_ns(void);

/* Print one measurement as a CSV line "BENCH,label,value,unit" on stdout,
 * so scripts can pick out measurement lines with grep. */
void     bench_log(const char *label, uint64_t value, const char *unit);

#endif
