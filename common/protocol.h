/* Constants from docs/PROTOCOL.md, plus the return codes every function uses.
 * Owner: Shalom. Do not change without Shalom's approval. */
#ifndef QD_PROTOCOL_H
#define QD_PROTOCOL_H

#define QD_PROTOCOL_VERSION   0x01

/* Frames (PROTOCOL.md section 2) */
#define QD_FRAME_HEADER_BYTES 5           /* 4-byte length + 1-byte type */
#define QD_FRAME_MAX          131072u     /* max value of the length field */

#define QD_F_HELLO            0x01
#define QD_F_KEM_PUBKEY       0x02
#define QD_F_KEM_CIPHERTEXT   0x03
#define QD_F_SECURE           0x10
#define QD_F_ERROR            0x31        /* only unencrypted during the handshake */

/* App types inside SECURE (section 5.1) */
#define QD_T_REGISTER         0x20
#define QD_T_UPLOAD_BEGIN     0x21
#define QD_T_CHUNK            0x22
#define QD_T_UPLOAD_END       0x23
#define QD_T_LIST_REQUEST     0x24
#define QD_T_DOWNLOAD_REQUEST 0x25
#define QD_T_KEY_REQUEST      0x26
#define QD_T_STATUS_REQUEST   0x27        /* reserved, not used in v1 */
#define QD_T_OK               0x30
#define QD_T_ERROR            0x31
#define QD_T_LIST_REPLY       0x32
#define QD_T_KEY_REPLY        0x35

/* Codes inside an ERROR body (section 5.3) */
#define QD_E_BAD_FORMAT       0x01
#define QD_E_UNKNOWN_ID       0x02
#define QD_E_ID_KEY_CONFLICT  0x03
#define QD_E_BAD_SIGNATURE    0x04
#define QD_E_HASH_MISMATCH    0x05
#define QD_E_SIZE_MISMATCH    0x06
#define QD_E_NOT_FOUND        0x07
#define QD_E_STORAGE          0x08
#define QD_E_BAD_VERSION      0x09
#define QD_E_TOO_LARGE        0x0A

/* Sizes in bytes. tests/test_main.c checks these against liboqs. */
#define QD_KEM_PK_BYTES       1184        /* ML-KEM-768 public key */
#define QD_KEM_CT_BYTES       1088        /* ML-KEM-768 ciphertext */
#define QD_SECRET_BYTES       32          /* ML-KEM shared secret */
#define QD_AES_KEY_BYTES      32
#define QD_GCM_NONCE_BYTES    12
#define QD_GCM_TAG_BYTES      16
#define QD_SIG_PK_BYTES       1952        /* ML-DSA-65 public key */
#define QD_SIG_BYTES          3309        /* ML-DSA-65 signature */
#define QD_SHA256_BYTES       32

/* Signed record (section 5.2) */
#define QD_RECORD_VERSION     0x01
#define QD_ID_MAX             64
#define QD_NAME_MAX           255
#define QD_RECORD_MAX         (1 + 1 + QD_ID_MAX + 2 + QD_NAME_MAX + 8 + QD_SHA256_BYTES + 8)  /* 371 */

#define QD_CHUNK_MAX          65536
/* Largest body inside SECURE: frame minus type byte, GCM tag and app type byte */
#define QD_BODY_MAX           (QD_FRAME_MAX - 1 - QD_GCM_TAG_BYTES - 1)

/* Return codes. 0 is success, everything else is negative. */
#define QD_OK                  0
#define QD_ERR_IO             -1   /* socket or read/write error */
#define QD_ERR_CLOSED         -2   /* the other side closed the connection cleanly */
#define QD_ERR_TOO_LARGE      -3   /* frame longer than QD_FRAME_MAX */
#define QD_ERR_FORMAT         -4   /* message does not follow PROTOCOL.md */
#define QD_ERR_BUFFER         -5   /* caller's buffer is too small */
#define QD_ERR_CRYPTO         -6   /* liboqs or OpenSSL call failed, or a check failed */
#define QD_ERR_NOT_IMPLEMENTED -7  /* stub, real code not written yet */
#define QD_ERR_ARG            -8   /* bad argument */
#define QD_ERR_FILE           -9   /* could not open/read/write a file */
#define QD_ERR_PEER           -10  /* the other side replied with ERROR */

/* Short description of a QD_ERR_* code, for printing. */
const char *qd_strerror(int code);

#endif
