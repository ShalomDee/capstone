/* QuantumDrive client: reads commands one line at a time and runs them.
 * Usage: client <id> [host] [port]        (defaults: 127.0.0.1 9000)
 * Commands can also be piped in, e.g. echo "list" | client alice
 * Owner: Shalom (commands: Chris). */
#include "commands.h"
#include "protocol.h"
#include "securenet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int client_open(const client_ctx *c, sec_session *s)
{
    int fd = net_connect(c->host, c->port);
    if (fd < 0) return fd;
    s->fd = fd;
    int rc = sec_handshake_client(fd, s);
    if (rc != QD_OK) sec_close(s);
    return rc;
}

static void help(void)
{
    printf("commands:\n"
           "  register                      create keys (if needed) and register this ID\n"
           "  upload <file>                 sign and upload a file\n"
           "  list                          list files on the server\n"
           "  download <owner_id> <file>    download a file and check its signature\n"
           "  verify <file>                 check a downloaded file's signature again\n"
           "  help                          show this list\n"
           "  quit                          exit\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <id> [host] [port]\n", argv[0]);
        return 1;
    }
    client_ctx c = {
        .id = argv[1],
        .host = argc > 2 ? argv[2] : "127.0.0.1",
        .port = argc > 3 ? atoi(argv[3]) : 9000,
        .key_dir = "keys",
        .data_dir = "client-data",
    };
    int interactive = isatty(STDIN_FILENO);
    if (interactive) printf("QuantumDrive client, ID \"%s\", server %s:%d. Type help.\n", c.id, c.host, c.port);

    char line[1024];
    for (;;) {
        if (interactive) { printf("> "); fflush(stdout); }
        if (!fgets(line, sizeof line, stdin)) break;

        char *cmd = strtok(line, " \t\r\n");
        char *a1 = strtok(NULL, " \t\r\n");
        char *a2 = strtok(NULL, " \t\r\n");
        if (!cmd) continue;

        int rc = QD_OK;
        if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) break;
        else if (!strcmp(cmd, "help")) help();
        else if (!strcmp(cmd, "register")) rc = cmd_register(&c);
        else if (!strcmp(cmd, "upload") && a1) rc = cmd_upload(&c, a1);
        else if (!strcmp(cmd, "list")) rc = cmd_list(&c);
        else if (!strcmp(cmd, "download") && a1 && a2) rc = cmd_download(&c, a1, a2);
        else if (!strcmp(cmd, "verify") && a1) rc = cmd_verify(&c, a1);
        else { printf("unknown command or missing argument; type help\n"); continue; }

        if (rc != QD_OK) printf("error: %s\n", qd_strerror(rc));
    }
    return 0;
}
