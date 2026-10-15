/* Reading and writing frames: [4-byte length][1-byte type][payload].
 * Also helpers to put numbers into bytes in big-endian order.
 * Owner: Shalom. Do not change without Shalom's approval. */
#ifndef QD_FRAMING_H
#define QD_FRAMING_H

#include <stddef.h>
#include <stdint.h>

/* Big-endian (most significant byte first) helpers. */
void     put_u16(uint8_t *p, uint16_t v);
void     put_u32(uint8_t *p, uint32_t v);
void     put_u64(uint8_t *p, uint64_t v);
uint16_t get_u16(const uint8_t *p);
uint32_t get_u32(const uint8_t *p);
uint64_t get_u64(const uint8_t *p);

/* Send or receive exactly n bytes on a socket, retrying short reads/writes.
 * read_all returns QD_ERR_CLOSED if the other side closed before any byte arrived. */
int write_all(int fd, const uint8_t *buf, size_t n);
int read_all(int fd, uint8_t *buf, size_t n);

/* Send one frame. len is the payload length (type byte not included). */
int frame_write(int fd, uint8_t type, const uint8_t *payload, size_t len);

/* Receive one frame into buf (capacity cap). On success *type and *len are set.
 * Returns QD_ERR_TOO_LARGE or QD_ERR_BUFFER without reading the payload;
 * the caller should then close the connection. */
int frame_read(int fd, uint8_t *type, uint8_t *buf, size_t cap, size_t *len);

#endif
