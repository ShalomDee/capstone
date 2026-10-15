/* STUB handlers. Chris fills in each handle_* function.
 * Message bodies and the checks to perform: docs/PROTOCOL.md section 6. */
#include "handlers.h"
#include "identity.h"
#include "protocol.h"

#include <string.h>

/* Send ERROR with a code and a short text (PROTOCOL.md section 5.3). */
static int send_error(server_conn *c, uint8_t code, const char *text)
{
    uint8_t body[128];
    size_t n = strlen(text);
    if (n > sizeof body - 1) n = sizeof body - 1;
    body[0] = code;
    memcpy(body + 1, text, n);
    return sec_send(c->s, QD_T_ERROR, body, 1 + n);
}

static int not_implemented(server_conn *c, const char *what)
{
    (void)what;
    return send_error(c, QD_E_BAD_FORMAT, "not implemented yet");
}

static int handle_register(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "register");
}

static int handle_upload_begin(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "upload_begin");
}

static int handle_chunk(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "chunk");
}

static int handle_upload_end(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "upload_end");
}

static int handle_list(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "list");
}

static int handle_download(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "download");
}

static int handle_key_request(server_conn *c, const uint8_t *body, size_t len)
{
    (void)body; (void)len;
    return not_implemented(c, "key_request");
}

int server_handle(server_conn *c, uint8_t type, const uint8_t *body, size_t len)
{
    switch (type) {
    case QD_T_REGISTER:         return handle_register(c, body, len);
    case QD_T_UPLOAD_BEGIN:     return handle_upload_begin(c, body, len);
    case QD_T_CHUNK:            return handle_chunk(c, body, len);
    case QD_T_UPLOAD_END:       return handle_upload_end(c, body, len);
    case QD_T_LIST_REQUEST:     return handle_list(c, body, len);
    case QD_T_DOWNLOAD_REQUEST: return handle_download(c, body, len);
    case QD_T_KEY_REQUEST:      return handle_key_request(c, body, len);
    default:                    return send_error(c, QD_E_BAD_FORMAT, "unknown message type");
    }
}
