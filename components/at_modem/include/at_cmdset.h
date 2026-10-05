#pragma once
/* Build-time choice of the AT command set (Kconfig AT_MODEM_CMDSET):
 *   M2M -- "M2M-AT Command Set" (AT*M2M*..., doc/M2M-AT Command Set.docx)
 *   OTH -- "OTH-AT Compatible Command Set" (AT*OTH*..., Essentials/MQTT/
 *          AWS/COAP volumes)
 * Only the chosen set's dispatch table is built, so the other set's
 * command handlers are dropped by the linker. Wi-Fi, sockets, HTTP, MQTT,
 * the web server and the security code underneath are shared. */
#include "sdkconfig.h"

#if CONFIG_AT_MODEM_CMDSET_OTH
#define AT_TAG             "*OTH*"
/* OTH Appendix A: 9 = ERR_COMMAND_NOT_EXIST */
#define AT_ERR_UNKNOWN_CMD 9
#else
#define AT_TAG             "*M2M*"
#define AT_ERR_UNKNOWN_CMD 99 /* AT_ERR_NOT_SUPPORTED */
#endif

/* Length of AT_TAG, which is always "*XXX*". */
#define AT_TAG_LEN 5
