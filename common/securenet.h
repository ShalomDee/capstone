/* The secure pipe: TCP connection, ML-KEM-768 handshake, AES-256-GCM messages.
 * Owner: Carvin. The function list is the shared contract (CLAUDE.md section 8);
 * do not change it without Shalom's approval. Byte layouts: docs/PROTOCOL.md. */
#ifndef QD_SECURENET_H
#define QD_SECURENET_H

#include <stddef.h>
#include <stdint.h>

/* One encrypted connection, filled in by sec_handshake_client/server.
 * "send" and "recv" are from this program's point of view: on the client,
 * send_key is the client-to-server key; on the server it is server-to-client. */
typedef struct {
    int      fd;                 /* TCP socket */
    uint8_t  send_key[32];       /* AES-256 key for messages we send */
    uint8_t  recv_key[32];       /* AES-256 key for messages we receive */
    uint64_t send_ctr;           /* message counters, used as the GCM nonce */
    uint64_t recv_ctr;
} sec_session;

/* Plain TCP. Return a socket (>= 0) or a negative QD_ERR_* code. */
int  net_listen(int port);
int  net_accept(int listen_fd);
int  net_connect(const char *host, int port);

/* Run the handshake on a connected socket and fill in *s. */
int  sec_handshake_client(int fd, sec_session *s);
int  sec_handshake_server(int fd, sec_session *s);

/* Send one encrypted message: app type plus body (at most QD_BODY_MAX bytes). */
int  sec_send(sec_session *s, uint8_t type, const uint8_t *body, size_t len);
/* Receive one encrypted message into buf (capacity cap). Sets *type and *len. */
int  sec_recv(sec_session *s, uint8_t *type, uint8_t *buf, size_t cap, size_t *len);
/* Close the socket and wipe the keys. */
void sec_close(sec_session *s);

#endif
