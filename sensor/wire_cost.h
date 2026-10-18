/* How many bytes each message puts on the wire, worked out from the layouts in
 * docs/PROTOCOL.md. Owner: Shalom.
 *
 * These numbers are COMPUTED from real message body sizes, not captured from a
 * socket, because securenet is still a stub. Once Carvin's code lands, count the
 * bytes sec_send actually writes and check they match these.
 * Not included: TCP/IP packet headers. */
#ifndef QD_WIRE_COST_H
#define QD_WIRE_COST_H

#include <stddef.h>
#include <stdint.h>

/* Extra bytes on every encrypted message: 4 length + 1 frame type + 1 app type + 16 GCM tag. */
#define WIRE_SECURE_OVERHEAD 22

/* One SECURE frame carrying a body of body_len bytes. */
uint64_t wire_secure(uint64_t body_len);

/* Sensor to server for one file: UPLOAD_BEGIN (record and signature), the
 * CHUNKs (64 KiB at most each), and UPLOAD_END. */
uint64_t wire_upload_c2s(size_t rec_len, size_t sig_len, uint64_t file_size);

/* Server to sensor for one file: the OK reply. */
uint64_t wire_upload_s2c(void);

/* Paid once per connection: the handshake (HELLO, KEM_PUBKEY, KEM_CIPHERTEXT, unencrypted). */
uint64_t wire_handshake_c2s(void);
uint64_t wire_handshake_s2c(void);

/* Paid once per connection: REGISTER with the sensor's ML-DSA-65 public key, and its OK. */
uint64_t wire_register_c2s(size_t id_len);
uint64_t wire_register_s2c(void);

#endif
