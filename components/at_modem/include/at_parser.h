#pragma once

#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AT_CMD_NAME_LEN   32
/* 16, not 8: MQTT_CONF's full form (link_id scheme host port path client_id
 * user password cert_name) alone needs 9 -- WF_EAPCERT's up to six
 * <type> <value> pairs need 12. The old cap of 8 silently truncated
 * MQTT_CONF's cert_name (argv[8]) on every call that supplied one. */
#define AT_MAX_PARAMS      16

/**
 * A parsed AT command line.
 *
 * Two shapes exist in the M2M-AT protocol (doc Ch.1.1/1.2):
 *   - "Special" commands: AT, ATE<0/1>, ATV -- bare "OK"/"ERROR" replies,
 *     no "*M2M*" wrapper, no "=" separator (param, if any, is glued directly
 *     onto the command, e.g. "ATE1").
 *   - Tagged commands: AT*M2M*<NAME>[=<params separated by spaces>] --
 *     replies wrapped as "*M2M*<NAME>:OK/ERROR ...".
 *
 * argc/argv are populated by at_dispatch.c calling at_tokenize_params() on
 * raw_params -- NOT by at_parse_line() itself. Commands whose last field is
 * arbitrary payload data that may itself contain spaces (e.g. NET_SEND) read
 * raw_params directly instead and do their own fixed-field parse, so the
 * generic tokenizer never gets a chance to mangle the data. See
 * at_dispatch.c's per-entry `raw` flag.
 */
typedef struct {
    bool  is_special;                       /* AT / ATE / ATV */
    char  name[AT_CMD_NAME_LEN];             /* e.g. "SYS_VER", "ATE", "AT" */
    char *raw_params;                        /* untouched substring after '=', or NULL */
    int   argc;
    char *argv[AT_MAX_PARAMS];               /* tokens of raw_params, quote-aware */
} at_command_t;

/**
 * Parse one already byte-unstuffed, CR/LF-stripped line in place.
 * `line` is modified (NUL possibly inserted right after the command name)
 * and must stay alive as long as `out`'s raw_params/argv pointers are used.
 * Does NOT tokenize raw_params -- see at_tokenize_params().
 *
 * Returns true if the line was recognized as a well-formed AT command
 * (either special or "AT*M2M*..."), false otherwise (caller should reply
 * with a generic ERROR).
 */
bool at_parse_line(char *line, at_command_t *out);

/**
 * Tokenize `raw` (mutated in place, NULs inserted at space boundaries) into
 * up to `max_argv` space-separated tokens honoring "quoted substrings".
 * Returns the token count. Safe to call with raw == NULL (returns 0).
 */
int at_tokenize_params(char *raw, char *argv[], int max_argv);

/**
 * True if this command was invoked in the doc's "Query" shape, "AT*M2M*
 * <NAME>=?" (Ch.1.2) -- i.e. raw_params tokenized to the single literal
 * token "?". Most Query+Set commands in this codebase use this to pick
 * their read vs. write branch; commands whose Query form takes real
 * parameters instead (e.g. SYS_CONF's "=<cmd> <index>") check argv
 * directly and don't use this helper.
 */
static inline bool at_is_query(const at_command_t *cmd)
{
    return cmd->argc == 1 && strcmp(cmd->argv[0], "?") == 0;
}

#ifdef __cplusplus
}
#endif
