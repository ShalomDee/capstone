/* STUB. Carvin replaces the body of every function with the real code.
 * Each stub returns QD_ERR_NOT_IMPLEMENTED so callers fail clearly instead of
 * pretending to be connected. */
#include "securenet.h"
#include "protocol.h"

#include <string.h>
#include <unistd.h>

int net_listen(int port)
{
    (void)port;
    return QD_ERR_NOT_IMPLEMENTED;
}

int net_accept(int listen_fd)
{
    (void)listen_fd;
    return QD_ERR_NOT_IMPLEMENTED;
}

int net_connect(const char *host, int port)
{
    (void)host; (void)port;
    return QD_ERR_NOT_IMPLEMENTED;
}

int sec_handshake_client(int fd, sec_session *s)
{
    (void)fd; (void)s;
    return QD_ERR_NOT_IMPLEMENTED;
}

int sec_handshake_server(int fd, sec_session *s)
{
    (void)fd; (void)s;
    return QD_ERR_NOT_IMPLEMENTED;
}

int sec_send(sec_session *s, uint8_t type, const uint8_t *body, size_t len)
{
    (void)s; (void)type; (void)body; (void)len;
    return QD_ERR_NOT_IMPLEMENTED;
}

int sec_recv(sec_session *s, uint8_t *type, uint8_t *buf, size_t cap, size_t *len)
{
    (void)s; (void)type; (void)buf; (void)cap; (void)len;
    return QD_ERR_NOT_IMPLEMENTED;
}

void sec_close(sec_session *s)
{
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    memset(s, 0, sizeof *s);
    s->fd = -1;
}
