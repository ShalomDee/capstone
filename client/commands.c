/* STUB commands. Chris fills in each one.
 * Message bodies: docs/PROTOCOL.md section 6. Use client_open() to connect. */
#include "commands.h"
#include "identity.h"
#include "protocol.h"

#include <stdio.h>

int cmd_register(const client_ctx *c)
{
    (void)c;
    printf("register: not implemented yet\n");
    return QD_ERR_NOT_IMPLEMENTED;
}

int cmd_upload(const client_ctx *c, const char *path)
{
    (void)c;
    printf("upload %s: not implemented yet\n", path);
    return QD_ERR_NOT_IMPLEMENTED;
}

int cmd_list(const client_ctx *c)
{
    (void)c;
    printf("list: not implemented yet\n");
    return QD_ERR_NOT_IMPLEMENTED;
}

int cmd_download(const client_ctx *c, const char *owner_id, const char *filename)
{
    (void)c;
    printf("download %s %s: not implemented yet\n", owner_id, filename);
    return QD_ERR_NOT_IMPLEMENTED;
}

int cmd_verify(const client_ctx *c, const char *path)
{
    (void)c;
    printf("verify %s: not implemented yet\n", path);
    return QD_ERR_NOT_IMPLEMENTED;
}
