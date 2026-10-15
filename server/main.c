/* QuantumDrive server: accept a client, run the handshake, then pass each
 * message to server_handle() until the client disconnects.
 * Usage: server [port] [storage_dir]      (defaults: 9000 server-data)
 * Clients are served one at a time. Owner: Shalom (handlers: Chris). */
#include "handlers.h"
#include "protocol.h"
#include "securenet.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static uint8_t body[QD_BODY_MAX];

static void serve_one(int fd, const char *storage_dir)
{
    sec_session s = { .fd = fd };
    int rc = sec_handshake_server(fd, &s);
    if (rc != QD_OK) {
        fprintf(stderr, "handshake failed: %s\n", qd_strerror(rc));
        sec_close(&s);
        return;
    }

    server_conn c = { .s = &s, .storage_dir = storage_dir };
    for (;;) {
        uint8_t type;
        size_t len;
        rc = sec_recv(&s, &type, body, sizeof body, &len);
        if (rc == QD_ERR_CLOSED) break;
        if (rc != QD_OK) {
            fprintf(stderr, "receive failed: %s\n", qd_strerror(rc));
            break;
        }
        rc = server_handle(&c, type, body, len);
        if (rc != QD_OK) {
            fprintf(stderr, "handler closed connection: %s\n", qd_strerror(rc));
            break;
        }
    }
    sec_close(&s);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 9000;
    const char *storage_dir = argc > 2 ? argv[2] : "server-data";

    if (mkdir(storage_dir, 0700) != 0 && errno != EEXIST) {
        perror(storage_dir);
        return 1;
    }

    int lfd = net_listen(port);
    if (lfd < 0) {
        fprintf(stderr, "cannot listen on port %d: %s\n", port, qd_strerror(lfd));
        return 1;
    }
    printf("server listening on port %d, storing files in %s/\n", port, storage_dir);

    for (;;) {
        int fd = net_accept(lfd);
        if (fd < 0) {
            fprintf(stderr, "accept failed: %s\n", qd_strerror(fd));
            continue;
        }
        serve_one(fd, storage_dir);
    }
}
