/* AT*M2M*NET_STATUS/CONN/DISCONN/SEND/SERVER -- doc Ch.4.2 socket/address
 * commands, on top of the net_link.c engine. NET_PING/DNS/SNTP/SNTPCONF/
 * DHCPS/DHCP live in cmd_net_svc.c; NET_DTMODE lives in cmd_net_dtmode.c. */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "at_commands.h"
#include "at_response.h"
#include "at_event.h"
#include "at_byte_stuffing.h"
#include "net_link.h"

static const char *link_type_str(net_link_type_t type)
{
    switch (type) {
    case NET_LINK_TCP: return "tcp";
    case NET_LINK_UDP: return "udp";
    case NET_LINK_SSL: return "ssl";
    default:           return "?";
    }
}

static bool parse_link_type(const char *s, net_link_type_t *out)
{
    if (strcasecmp(s, "tcp") == 0) { *out = NET_LINK_TCP; return true; }
    if (strcasecmp(s, "udp") == 0) { *out = NET_LINK_UDP; return true; }
    if (strcasecmp(s, "ssl") == 0) { *out = NET_LINK_SSL; return true; }
    return false;
}

/* AT*M2M*NET_STATUS=? -- Query only. */
void cmd_net_status(const at_command_t *cmd)
{
    net_link_t links[NET_MAX_LINKS];
    net_link_snapshot(links);

    for (int i = 0; i < NET_MAX_LINKS; i++) {
        if (!links[i].in_use) {
            continue;
        }
        at_reply_line("NET_STATUS:IND %d %d %s %s %d %d",
                      i, links[i].is_server_role ? 1 : 0, link_type_str(links[i].type),
                      links[i].is_listener ? "0.0.0.0" : links[i].remote_ip,
                      links[i].is_listener ? 0 : links[i].remote_port,
                      links[i].local_port);
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_CONN=<link_id> <type> <remote_ip> <remote_port> <local_port>
 * [keep_alive] [cert_name] -- keep_alive (TCP/SSL keep-alive tuning) is
 * accepted but not yet applied. cert_name (SSL only) is a client cert+key
 * file for mutual TLS, previously stored via NET_HTTPDOWNLOAD; omitted, an
 * SSL connect still validates the server against the default CA bundle
 * (doc's "server-only validation" case, see net_link.c's connect_ssl()).
 *
 * The doc's example flow shows OK immediately followed by an async
 * NET_CONN:DONE, implying a non-blocking connect; this implementation
 * instead does a bounded *blocking* connect (net_link.c's
 * connect_with_timeout()/connect_ssl(), capped well under the AT dispatcher
 * stalling noticeably) and only replies once the outcome is known -- OK+DONE
 * land together rather than genuinely overlapping with later commands,
 * which is simpler and doesn't change what a host sees on the wire. */
void cmd_net_conn(const at_command_t *cmd)
{
    if (cmd->argc < 5) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    int link_id = atoi(cmd->argv[0]);
    net_link_type_t type;
    if (!parse_link_type(cmd->argv[1], &type)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    const char *ip = cmd->argv[2];
    long port = atol(cmd->argv[3]);
    long local_port = atol(cmd->argv[4]);
    if (port <= 0 || port > 65535 || local_port < 0 || local_port > 65535) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    const char *cert_name = (cmd->argc >= 7) ? cmd->argv[6] : NULL; /* argv[5]=keep_alive */

    int rc = net_link_connect(link_id, type, ip, (uint16_t)port, (uint16_t)local_port, cert_name);
    if (rc == -1) {
        at_reply_error(cmd->name, AT_ERR_STATE); /* link_id already in use */
        return;
    }
    if (rc != 0) {
        at_reply_error(cmd->name, 4); /* Appendix C: ERR_CONNECTION_ESTABLISHMENT */
        return;
    }
    at_reply_ok(cmd->name, NULL);
    at_event_post("NET_CONN:DONE %d", link_id);
}

/* AT*M2M*NET_DISCONN[=<link_id>] -- link_id omitted closes every link. */
void cmd_net_disconn(const at_command_t *cmd)
{
    if (cmd->argc == 0) {
        for (int i = 0; i < NET_MAX_LINKS; i++) {
            net_link_close(i);
        }
        at_reply_ok(cmd->name, NULL);
        for (int i = 0; i < NET_MAX_LINKS; i++) {
            at_event_post("NET_DISCONN:DONE %d", i);
        }
        return;
    }

    int link_id = atoi(cmd->argv[0]);
    if (link_id < 0 || link_id >= NET_MAX_LINKS) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    net_link_close(link_id);
    at_reply_ok(cmd->name, NULL);
    at_event_post("NET_DISCONN:DONE %d", link_id);
}

/* AT*M2M*NET_SEND=<link_id> <size> <payload> -- registered with the
 * dispatch table's `raw` flag: <payload> may itself contain spaces (once
 * byte-stuffed per doc Ch.1.4, it never contains an unescaped CR, but a
 * literal space is not special-cased there and passes straight through
 * unescaped), so this hand-parses cmd->raw_params instead of using argv. */
void cmd_net_send(const at_command_t *cmd)
{
    char *p = cmd->raw_params;
    if (!p) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    while (*p == ' ') {
        p++;
    }
    char *link_tok = p;
    while (*p && *p != ' ') {
        p++;
    }
    if (!*p) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    *p++ = '\0';

    while (*p == ' ') {
        p++;
    }
    char *size_tok = p;
    while (*p && *p != ' ') {
        p++;
    }
    if (!*p) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    *p++ = '\0';
    char *payload = p; /* everything else, verbatim */

    int link_id = atoi(link_tok);
    long size = atol(size_tok);
    if (link_id < 0 || link_id >= NET_MAX_LINKS || size < 0 || size > 8192) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }

    static uint8_t decoded[8192];
    size_t decoded_len = at_byte_stuff_decode(payload, strlen(payload), decoded, sizeof(decoded));
    if ((long)decoded_len != size) {
        at_reply_error(cmd->name, AT_ERR_ARG); /* <size> didn't match the actual payload */
        return;
    }

    if (net_link_send(link_id, decoded, decoded_len) != ESP_OK) {
        at_reply_error(cmd->name, AT_ERR_STATE);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}

/* AT*M2M*NET_SERVER -- Query lists active listeners/UDP servers; Set
 * enables/disables one. No link_id parameter (doc Ch.4.2): a TCP/SSL
 * listener occupies its own link slot distinct from the client connections
 * it later accepts (see net_link.h); a UDP "server" link IS the slot. */
void cmd_net_server(const at_command_t *cmd)
{
    if (at_is_query(cmd) || cmd->argc == 0) {
        net_link_t links[NET_MAX_LINKS];
        net_link_snapshot(links);
        for (int i = 0; i < NET_MAX_LINKS; i++) {
            if (links[i].in_use && links[i].is_server_role) {
                at_reply_line("NET_SERVER:IND %s %d", link_type_str(links[i].type), links[i].local_port);
            }
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }

    if (cmd->argc < 3) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    int mode = atoi(cmd->argv[0]);
    net_link_type_t type;
    if (!parse_link_type(cmd->argv[1], &type)) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    long port = atol(cmd->argv[2]);
    if (port <= 0 || port > 65535) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    /* argv[3] cert_name: server certificate+key file, required when type is
     * ssl (doc), ignored otherwise. */
    const char *cert_name = (cmd->argc >= 4) ? cmd->argv[3] : NULL;

    if (mode == 0) {
        int id = net_link_find_server(type, (uint16_t)port);
        if (id >= 0) {
            net_link_close(id);
        }
        at_reply_ok(cmd->name, NULL);
        return;
    }
    if (mode != 1) {
        at_reply_error(cmd->name, AT_ERR_ARG);
        return;
    }
    if (net_link_find_server(type, (uint16_t)port) >= 0) {
        at_reply_error(cmd->name, 10); /* Appendix C: ERR_ADDRESS_IN_USE */
        return;
    }

    int id;
    if (type == NET_LINK_SSL) {
        id = net_link_listen_ssl((uint16_t)port, cert_name);
    } else if (type == NET_LINK_TCP) {
        id = net_link_listen_tcp((uint16_t)port);
    } else {
        id = net_link_listen_udp((uint16_t)port);
    }
    if (id < 0) {
        at_reply_error(cmd->name, id == -1 ? 1 /* ERR_SOCKET_NOT_AVAIL */ : AT_ERR_GENERIC);
        return;
    }
    at_reply_ok(cmd->name, NULL);
}
