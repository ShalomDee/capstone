#include "reading.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int id_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

static int id_bytes_ok(const char *s, size_t n)
{
    if (n < 1 || n > QD_ID_MAX) return 0;
    for (size_t i = 0; i < n; i++)
        if (!id_char_ok(s[i])) return 0;
    return 1;
}

int reading_id_ok(const char *id)
{
    return id && id_bytes_ok(id, strnlen(id, QD_ID_MAX + 1));
}

int reading_valid(const reading *r)
{
    return r && reading_id_ok(r->id) &&
           r->seq <= READING_SEQ_MAX &&
           r->time >= READING_TIME_MIN && r->time <= READING_TIME_MAX &&
           r->temp_tenths >= READING_TEMP_MIN && r->temp_tenths <= READING_TEMP_MAX &&
           r->humidity >= 0 && r->humidity <= 100 &&
           r->soil >= 0 && r->soil <= 100;
}

int reading_simulate(const char *id, uint32_t seq, int64_t time, reading *out)
{
    if (!out || !reading_id_ok(id)) return QD_ERR_ARG;
    uint32_t x = seq * 2654435761u;                 /* scramble seq into fake values */
    memset(out, 0, sizeof *out);
    strcpy(out->id, id);
    out->seq = seq;
    out->time = time;
    out->temp_tenths = 180 + (int)(x % 81);         /* 18.0 to 26.0 C */
    out->humidity = 35 + (int)((x >> 8) % 30);      /* 35 to 64 % */
    out->soil = 20 + (int)((x >> 16) % 25);         /* 20 to 44 % */
    return reading_valid(out) ? QD_OK : QD_ERR_ARG;
}

int reading_format(const reading *r, char *buf, size_t cap, size_t *len)
{
    if (!r || !buf || !len) return QD_ERR_ARG;
    if (!reading_valid(r)) return QD_ERR_FORMAT;
    int t = r->temp_tenths < 0 ? -r->temp_tenths : r->temp_tenths;
    int n = snprintf(buf, cap, "v1,%s,%u,%lld,%s%d.%d,%d,%d\n",
                     r->id, (unsigned)r->seq, (long long)r->time,
                     r->temp_tenths < 0 ? "-" : "", t / 10, t % 10, r->humidity, r->soil);
    if (n < 0) return QD_ERR_FORMAT;
    if ((size_t)n >= cap) return QD_ERR_BUFFER;
    *len = (size_t)n;
    return QD_OK;
}

/* Unsigned decimal number: digits only, no sign, no leading zeros except "0". */
static int parse_uint(const char *s, size_t n, uint64_t max, uint64_t *out)
{
    if (n < 1 || n > 19) return 0;                  /* 19 digits always fits in 64 bits */
    if (n > 1 && s[0] == '0') return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (uint64_t)(s[i] - '0');
    }
    if (v > max) return 0;
    *out = v;
    return 1;
}

/* Temperature: optional '-', whole degrees, '.', exactly one digit. "-0.0" is refused
 * so every reading has only one way to be written. */
static int parse_temp(const char *s, size_t n, int *out)
{
    int neg = n > 0 && s[0] == '-';
    if (neg) { s++; n--; }
    if (n < 3 || s[n - 2] != '.' || s[n - 1] < '0' || s[n - 1] > '9') return 0;
    uint64_t whole;
    if (!parse_uint(s, n - 2, 100, &whole)) return 0;
    int t = (int)whole * 10 + (s[n - 1] - '0');
    if (neg && t == 0) return 0;
    *out = neg ? -t : t;
    return 1;
}

int reading_parse(const char *line, size_t len, reading *out)
{
    if (!line || !out) return QD_ERR_ARG;
    if (len < 2 || len > READING_LINE_MAX || line[len - 1] != '\n') return QD_ERR_FORMAT;
    len--;                                          /* drop the newline */

    const char *f[READING_FIELDS];
    size_t fl[READING_FIELDS];
    int nf = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || line[i] == ',') {
            if (nf == READING_FIELDS) return QD_ERR_FORMAT;   /* too many fields */
            f[nf] = line + start;
            fl[nf] = i - start;
            nf++;
            start = i + 1;
        }
    }
    if (nf != READING_FIELDS) return QD_ERR_FORMAT;

    reading r;
    memset(&r, 0, sizeof r);
    uint64_t v;
    if (fl[0] != 2 || memcmp(f[0], "v1", 2) != 0) return QD_ERR_FORMAT;
    if (!id_bytes_ok(f[1], fl[1])) return QD_ERR_FORMAT;
    memcpy(r.id, f[1], fl[1]);
    if (!parse_uint(f[2], fl[2], READING_SEQ_MAX, &v)) return QD_ERR_FORMAT;
    r.seq = (uint32_t)v;
    if (!parse_uint(f[3], fl[3], READING_TIME_MAX, &v)) return QD_ERR_FORMAT;
    r.time = (int64_t)v;
    if (!parse_temp(f[4], fl[4], &r.temp_tenths)) return QD_ERR_FORMAT;
    if (!parse_uint(f[5], fl[5], 100, &v)) return QD_ERR_FORMAT;
    r.humidity = (int)v;
    if (!parse_uint(f[6], fl[6], 100, &v)) return QD_ERR_FORMAT;
    r.soil = (int)v;
    if (!reading_valid(&r)) return QD_ERR_FORMAT;   /* time too early, temp out of range */
    *out = r;
    return QD_OK;
}

int reading_check_batch(const reading *r, size_t n, const char **why)
{
    const char *dummy;
    if (!why) why = &dummy;
    *why = "";
    if (!r || n == 0) { *why = "no readings"; return QD_ERR_ARG; }
    for (size_t i = 0; i < n; i++) {
        if (!reading_valid(&r[i])) { *why = "a field is out of range"; return QD_ERR_FORMAT; }
        if (i == 0) continue;
        if (strcmp(r[i].id, r[0].id) != 0) { *why = "readings from more than one sensor"; return QD_ERR_FORMAT; }
        if (r[i].seq == r[i - 1].seq) { *why = "duplicate sequence number"; return QD_ERR_FORMAT; }
        if (r[i].seq < r[i - 1].seq) { *why = "sequence numbers out of order"; return QD_ERR_FORMAT; }
        if (r[i].seq != r[i - 1].seq + 1) { *why = "gap in sequence numbers"; return QD_ERR_FORMAT; }
        if (r[i].time < r[i - 1].time) { *why = "time goes backwards"; return QD_ERR_FORMAT; }
    }
    return QD_OK;
}

int reading_filename(const char *id, uint32_t first, uint32_t last, char *buf, size_t cap)
{
    if (!buf || !reading_id_ok(id) || first > last || last > READING_SEQ_MAX) return QD_ERR_ARG;
    int n = first == last
        ? snprintf(buf, cap, "%s-%06u.csv", id, (unsigned)first)
        : snprintf(buf, cap, "%s-%06u-%06u.csv", id, (unsigned)first, (unsigned)last);
    if (n < 0) return QD_ERR_FORMAT;
    if ((size_t)n >= cap) return QD_ERR_BUFFER;
    return QD_OK;
}

int reading_read_file(const char *path, reading *out, size_t cap, size_t *n, const char **why)
{
    const char *dummy;
    if (!why) why = &dummy;
    *why = "";
    if (!path || !out || !n) return QD_ERR_ARG;
    FILE *fp = fopen(path, "rb");
    if (!fp) { *why = "cannot open file"; return QD_ERR_FILE; }

    char *line = NULL;
    size_t line_cap = 0, count = 0;
    ssize_t got;
    int rc = QD_OK;
    while ((got = getline(&line, &line_cap, fp)) != -1) {
        if (count == cap) { *why = "more readings than expected"; rc = QD_ERR_BUFFER; break; }
        if (reading_parse(line, (size_t)got, &out[count]) != QD_OK) {
            *why = "a line is not a valid v1 reading";
            rc = QD_ERR_FORMAT;
            break;
        }
        count++;
    }
    free(line);
    fclose(fp);
    if (rc != QD_OK) return rc;
    *n = count;
    return reading_check_batch(out, count, why);
}
