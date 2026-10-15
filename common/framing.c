#include "framing.h"
#include "protocol.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

void put_u16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
void put_u32(uint8_t *p, uint32_t v) { for (int i = 3; i >= 0; i--) { p[i] = v; v >>= 8; } }
void put_u64(uint8_t *p, uint64_t v) { for (int i = 7; i >= 0; i--) { p[i] = v; v >>= 8; } }

uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
uint32_t get_u32(const uint8_t *p) { uint32_t v = 0; for (int i = 0; i < 4; i++) v = v << 8 | p[i]; return v; }
uint64_t get_u64(const uint8_t *p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v = v << 8 | p[i]; return v; }

int write_all(int fd, const uint8_t *buf, size_t n)
{
    while (n > 0) {
        /* MSG_NOSIGNAL: if the other side is gone, return an error instead of killing the program */
        ssize_t w = send(fd, buf, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return QD_ERR_IO;
        }
        buf += w;
        n -= (size_t)w;
    }
    return QD_OK;
}

int read_all(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r == 0) return got == 0 ? QD_ERR_CLOSED : QD_ERR_IO;   /* closed mid-message is an error */
        if (r < 0) {
            if (errno == EINTR) continue;
            return QD_ERR_IO;
        }
        got += (size_t)r;
    }
    return QD_OK;
}

int frame_write(int fd, uint8_t type, const uint8_t *payload, size_t len)
{
    if (len > QD_FRAME_MAX - 1) return QD_ERR_TOO_LARGE;
    if (len > 0 && payload == NULL) return QD_ERR_ARG;

    /* Header and payload go out in one send. Two small sends can be delayed by
     * TCP (Nagle's algorithm), which would distort timing measurements. */
    size_t total = QD_FRAME_HEADER_BYTES + len;
    uint8_t *out = malloc(total);
    if (!out) return QD_ERR_IO;
    put_u32(out, (uint32_t)(len + 1));
    out[4] = type;
    if (len > 0) memcpy(out + QD_FRAME_HEADER_BYTES, payload, len);

    int rc = write_all(fd, out, total);
    free(out);
    return rc;
}

int frame_read(int fd, uint8_t *type, uint8_t *buf, size_t cap, size_t *len)
{
    uint8_t hdr[QD_FRAME_HEADER_BYTES];
    int rc = read_all(fd, hdr, 4);
    if (rc != QD_OK) return rc;

    uint32_t flen = get_u32(hdr);
    if (flen == 0) return QD_ERR_FORMAT;
    if (flen > QD_FRAME_MAX) return QD_ERR_TOO_LARGE;
    if (flen - 1 > cap) return QD_ERR_BUFFER;

    rc = read_all(fd, hdr + 4, 1);
    if (rc != QD_OK) return rc == QD_ERR_CLOSED ? QD_ERR_IO : rc;
    if (flen > 1) {
        rc = read_all(fd, buf, flen - 1);
        if (rc != QD_OK) return rc == QD_ERR_CLOSED ? QD_ERR_IO : rc;
    }
    *type = hdr[4];
    *len = flen - 1;
    return QD_OK;
}
