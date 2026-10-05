#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse and execute one complete, CR-stripped AT command line (mutable
 * buffer, may be tokenized in place). Looks up the command in the static
 * dispatch table and invokes its handler, which is responsible for sending
 * the appropriate OK/ERROR response itself. Unknown/malformed lines get a
 * generic ERROR reply.
 */
void at_dispatch_line(char *line);

#ifdef __cplusplus
}
#endif
