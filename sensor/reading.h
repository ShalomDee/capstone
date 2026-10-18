/* Farm sensor readings: the agreed v1 text format (one CSV line per reading),
 * strict parsing, batch checks and file names. Owner: Shalom.
 *
 * One reading is one newline-terminated line:
 *     v1,<sensor id>,<seq>,<unix time>,<temp C, one decimal>,<humidity %>,<soil %>\n
 *     v1,field-a-01,42,1792345678,21.5,43,31\n
 *
 * A file holds 1 or more readings from one sensor, with consecutive sequence
 * numbers. Its name shows the first and last sequence number:
 *     field-a-01-000042.csv           one reading
 *     field-a-01-000040-000049.csv    readings 40 to 49
 * One signature covers the whole file (docs/PROTOCOL.md section 5.2). */
#ifndef QD_READING_H
#define QD_READING_H

#include "protocol.h"

#include <stddef.h>
#include <stdint.h>

#define READING_FIELDS     7
#define READING_LINE_MAX   128          /* longest possible line is 100 bytes */
#define READING_SEQ_MAX    999999u      /* file names pad to 6 digits so they sort */
#define READING_TIME_MIN   1577836800   /* 2020-01-01 UTC: earlier means the sensor clock is not set */
#define READING_TIME_MAX   4102444800   /* 2100-01-01 UTC: later means a broken clock */
#define READING_TEMP_MIN   -400         /* -40.0 C, in tenths of a degree */
#define READING_TEMP_MAX   850          /*  85.0 C */

typedef struct {
    char     id[QD_ID_MAX + 1];  /* letters, digits, '-' and '_' only */
    uint32_t seq;                /* counts up from 0 */
    int64_t  time;               /* Unix seconds, UTC, when the reading was TAKEN */
    int      temp_tenths;        /* temperature in tenths of a degree C: 21.5 C is 215 */
    int      humidity;           /* relative air humidity, whole %, 0 to 100 */
    int      soil;               /* soil moisture, whole %, 0 to 100 */
} reading;

/* 1 if id is 1 to 64 characters of letters, digits, '-' or '_'. */
int reading_id_ok(const char *id);

/* 1 if every field is inside its allowed range. */
int reading_valid(const reading *r);

/* Make plausible fake values for one reading (same inputs give the same values). */
int reading_simulate(const char *id, uint32_t seq, int64_t time, reading *out);

/* Write r as one line, newline included, into buf. *len is set to its length. */
int reading_format(const reading *r, char *buf, size_t cap, size_t *len);

/* Parse exactly one line (len bytes, must end in '\n'). Strict: no spaces,
 * no leading zeros, no '\r', exactly one decimal on the temperature. */
int reading_parse(const char *line, size_t len, reading *out);

/* Check n readings meant for one file: same sensor ID, each sequence number
 * exactly one more than the last (so no gaps, duplicates or reordering), and
 * time never going backwards. On failure *why (if not NULL) says what broke. */
int reading_check_batch(const reading *r, size_t n, const char **why);

/* File name for readings first..last of sensor id (see top of this file). */
int reading_filename(const char *id, uint32_t first, uint32_t last, char *buf, size_t cap);

/* Read a whole readings file: parse every line into out (capacity cap) and run
 * reading_check_batch on the result. *n is set to the number of readings. */
int reading_read_file(const char *path, reading *out, size_t cap, size_t *n, const char **why);

#endif
