/* Client commands. Owner: Chris (client_open is in main.c, owner Shalom). */
#ifndef QD_CLIENT_COMMANDS_H
#define QD_CLIENT_COMMANDS_H

#include "securenet.h"

/* Settings for this client, from the command line. */
typedef struct {
    const char *id;        /* this user's or device's ID */
    const char *host;      /* server address */
    int         port;
    const char *key_dir;   /* where this ID's key pair is kept */
    const char *data_dir;  /* where downloads are saved */
} client_ctx;

/* Connect to the server and run the handshake. Close with sec_close(s). */
int client_open(const client_ctx *c, sec_session *s);

/* Each command returns 0 on success or a negative QD_ERR_* code. */
int cmd_register(const client_ctx *c);
int cmd_upload(const client_ctx *c, const char *path);
int cmd_list(const client_ctx *c);
int cmd_download(const client_ctx *c, const char *owner_id, const char *filename);
int cmd_verify(const client_ctx *c, const char *path);

#endif
