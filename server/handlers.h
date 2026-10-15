/* Server-side message handlers. Owner: Chris. */
#ifndef QD_SERVER_HANDLERS_H
#define QD_SERVER_HANDLERS_H

#include <stddef.h>
#include <stdint.h>
#include "securenet.h"

/* Everything a handler needs about one client connection. */
typedef struct {
    sec_session *s;
    const char  *storage_dir;   /* where uploaded files and registered keys are kept */
    /* Chris: add upload-in-progress state here (record, signature, bytes received, open file). */
} server_conn;

/* Handle one decrypted message from the client and send any reply.
 * Return 0 to keep the connection open, or a negative QD_ERR_* code to close it. */
int server_handle(server_conn *c, uint8_t type, const uint8_t *body, size_t len);

#endif
