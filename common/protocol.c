#include "protocol.h"

const char *qd_strerror(int code)
{
    switch (code) {
    case QD_OK:                  return "ok";
    case QD_ERR_IO:              return "network or I/O error";
    case QD_ERR_CLOSED:          return "connection closed by the other side";
    case QD_ERR_TOO_LARGE:       return "message too large";
    case QD_ERR_FORMAT:          return "badly formed message";
    case QD_ERR_BUFFER:          return "buffer too small";
    case QD_ERR_CRYPTO:          return "cryptography error or check failed";
    case QD_ERR_NOT_IMPLEMENTED: return "not implemented yet (stub)";
    case QD_ERR_ARG:             return "bad argument";
    case QD_ERR_FILE:            return "file error";
    case QD_ERR_PEER:            return "the other side reported an error";
    default:                     return "unknown error";
    }
}
