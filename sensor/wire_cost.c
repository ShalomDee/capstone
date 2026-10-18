#include "wire_cost.h"
#include "protocol.h"

uint64_t wire_secure(uint64_t body_len)
{
    return WIRE_SECURE_OVERHEAD + body_len;
}

uint64_t wire_upload_c2s(size_t rec_len, size_t sig_len, uint64_t file_size)
{
    uint64_t begin = wire_secure(2 + rec_len + 2 + sig_len);
    uint64_t chunks = (file_size + QD_CHUNK_MAX - 1) / QD_CHUNK_MAX;    /* 0 for an empty file */
    uint64_t chunk_bytes = chunks * wire_secure(8) + file_size;         /* 8-byte offset each */
    uint64_t end = wire_secure(0);
    return begin + chunk_bytes + end;
}

uint64_t wire_upload_s2c(void)
{
    return wire_secure(0);
}

uint64_t wire_handshake_c2s(void)
{
    return (QD_FRAME_HEADER_BYTES + 1) + (QD_FRAME_HEADER_BYTES + QD_KEM_CT_BYTES);
}

uint64_t wire_handshake_s2c(void)
{
    return QD_FRAME_HEADER_BYTES + QD_KEM_PK_BYTES;
}

uint64_t wire_register_c2s(size_t id_len)
{
    return wire_secure(1 + id_len + 2 + QD_SIG_PK_BYTES);
}

uint64_t wire_register_s2c(void)
{
    return wire_secure(0);
}
