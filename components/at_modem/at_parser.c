#include <string.h>
#include <strings.h>

#include "at_parser.h"

/* "AT*M2M*" prefix length: A T * M 2 M * */
#define M2M_PREFIX     "AT*M2M*"
#define M2M_PREFIX_LEN 7

int at_tokenize_params(char *p, char *argv[], int max_argv)
{
    int argc = 0;
    if (!p) {
        return 0;
    }
    while (*p && argc < max_argv) {
        while (*p == ' ') {
            p++;
        }
        if (!*p) {
            break;
        }
        if (*p == '"') {
            p++;
            argv[argc++] = p;
            char *end_quote = strchr(p, '"');
            if (end_quote) {
                *end_quote = '\0';
                p = end_quote + 1;
            } else {
                p += strlen(p);
            }
        } else {
            argv[argc++] = p;
            while (*p && *p != ' ') {
                p++;
            }
            if (*p) {
                *p = '\0';
                p++;
            }
        }
    }
    return argc;
}

bool at_parse_line(char *line, at_command_t *out)
{
    memset(out, 0, sizeof(*out));

    if (strncasecmp(line, "AT", 2) != 0) {
        return false;
    }
    char *rest = line + 2;

    if (*rest == '\0') {
        /* bare "AT" */
        strcpy(out->name, "AT");
        out->is_special = true;
        return true;
    }

    if (strncasecmp(rest, M2M_PREFIX + 2, M2M_PREFIX_LEN - 2) == 0) {
        /* "AT*M2M*<NAME>[=<params>]" */
        rest += (M2M_PREFIX_LEN - 2);
        char *eq = strchr(rest, '=');
        size_t name_len = eq ? (size_t)(eq - rest) : strlen(rest);
        if (name_len == 0 || name_len >= AT_CMD_NAME_LEN) {
            return false;
        }
        memcpy(out->name, rest, name_len);
        out->name[name_len] = '\0';
        out->is_special = false;
        out->raw_params = eq ? eq + 1 : NULL;
        return true;
    }

    if (strncasecmp(rest, "E", 1) == 0) {
        /* "ATE0" / "ATE1" */
        strcpy(out->name, "ATE");
        out->is_special = true;
        if (rest[1] != '\0') {
            out->argv[out->argc++] = rest + 1;
        }
        return true;
    }

    if (strncasecmp(rest, "V", 1) == 0) {
        /* "ATV" (TBD per doc) */
        strcpy(out->name, "ATV");
        out->is_special = true;
        return true;
    }

    return false;
}
