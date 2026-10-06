|Supported Targets|ESP32-C3|
|-|-|

# M2M ESP32-C3 — M2M-AT / OTH-AT Command Set

**This repository (OTH_ESP32_C) builds the OTH-AT command set.** The
firmware answers either `AT*M2M*...` (M2M-AT Command Set) or `AT*OTH*...`
(OTH-AT Compatible Command Set: Essentials, MQTT, AWS volumes), chosen at
build time with menuconfig → *AT Modem* → *AT command set*
(`CONFIG_AT_MODEM_CMDSET_M2M` / `CONFIG_AT_MODEM_CMDSET_OTH`). Only the
chosen set's handlers are linked in; Wi-Fi, sockets, HTTP, MQTT, AWS IoT,
the configuration web UI and the EN 18031-1 security features are shared.
This repository's `sdkconfig` selects OTH. The per-command status, the
decisions taken where the OTH-AT guides are silent, and the open items are
in `doc/OTH-AT_Command_Status.xlsx`; the OTH-AT phases are at the end of
*Progress* below (Phase 16-22).


AT-command modem (`components/at_modem/`) implementing the protocol
documented in `M2M-AT Command Set.docx`
(`C:\Doc\1.Projects\ESP\표준모델\03_설계문서\`). Ported from the sibling
`ESP32_N4` project (original ESP32/Xtensa target) to this board's
ESP32-C3 (RISC-V).

Being built in phases per
`C:\Users\crowm\.claude\plans\tingly-gathering-parasol.md` — see that plan
for the full command-by-command mapping and rationale.

## Progress

- [x] **Phase 0** — project scaffold: UART transport, event queue,
      byte-stuffing, dispatch engine, `AT`/`ATE`/`ATV` only.
- [x] **Phase 1 (core)** — `SYS_VER`/`SYS_MAC`/`SYS_RST`/`SYS_FACTORY`/
      `SYS_UART`/`SYS_CONF`/`SYS_COUNTRY` (`cmd_sys.c`) and `WF_MODE`/
      `WF_SCAN`/`WF_CONN`/`WF_DISCONN`/`WF_IPSTATUS`/`WF_APSTART`/
      `WF_APSTATION` (`cmd_wifi.c`), plus real Wi-Fi driver bring-up
      (`at_wifi_init()`) turning WIFI_EVENT/IP_EVENT into the Ch.7 async
      notifications (`WF_CONN:DONE`, `NET_IP:IND`, `WF_DISCONN:DONE`,
      `STA_ASSOCIATED`/`STA_DISASSOCIATED`).
      Hardware-verified 2026-08-29 over COM7 (native USB Serial/JTAG):
      `SYS_VER`/`SYS_MAC`/`SYS_COUNTRY` get+set/`SYS_UART`/`SYS_CONF`
      get+set+reserved-index-error/`SYS_RST` (confirmed real reboot, not a
      crash) all round-tripped correctly; `WF_MODE` get+set; `WF_SCAN`
      returned real nearby APs with correct SSID/RSSI/BSSID/channel/auth;
      `WF_APSTART`+`WF_IPSTATUS`(AP)+`WF_APSTATION` round-tripped on a live
      SoftAP; `WF_CONN` against a real WPA2 AP round-tripped with correct
      async `WF_CONN:DONE` + `NET_IP:IND <ip> <netmask> <gw> <dns>`,
      `WF_IPSTATUS`/`WF_CONN=?` matched the live association, and
      `WF_DISCONN` correctly suppressed the unsolicited-loss notification
      (doc §7.2: `WF_DISCONN:DONE` is only for a loss *without* a preceding
      host `WF_DISCONN`).
      `WF_APMODE` (auto-reconnect profile), `WF_EAPCONF`/`WF_EAPCERT` (802.1X
      enterprise), and `WF_WPS` were deferred here and implemented later,
      see **Phase 7**. `SYS_LSLEEP`/`SYS_ANTENNA` were deferred here too and
      implemented 2026-09-26: `SYS_LSLEEP` modes 0/1/3 map directly onto
      `esp_wifi_set_ps()` (`WIFI_PS_NONE`/`MIN_MODEM`/`MAX_MODEM`, real Wi-Fi
      radio power saving); mode 2 (system-wide light sleep) needs
      `CONFIG_PM_ENABLE`, off in this project's `sdkconfig` -- turning it on
      is a separate, riskier change (this project's AT/console channel runs
      over native USB Serial/JTAG, whose behavior across light sleep needs
      its own verification), so mode=2 replies the doc's own "reason:
      0-not supported" instead of guessing. `SYS_ANTENNA`: this project's
      ESP32-C3 boards have a single onboard PCB antenna with no RF switch to
      an external-antenna connector, so type=0 (already what's wired)
      succeeds and persists, type=1 replies "reason: 0-not supported".
      Both persist their setting in the shared `m2m_sys` NVS namespace and
      are reapplied at boot (`at_wifi_init()`, same pattern as
      `SYS_COUNTRY`). Hardware-verified 2026-09-26 over COM7: mode/type
      transitions, doc-defined error responses, and — for `SYS_LSLEEP` —
      persistence across a real `SYS_RST` reboot, all confirmed
      (`tools/at_test.py`'s new `sys_lsleep`/`sys_antenna` sequences).
      Still deferred: `SYS_DSLEEP` (the doc's own text for it is empty --
      title only, no body -- so there is nothing to implement against until
      the spec is completed).
- [x] **Phase 2** — `NET_STATUS`/`NET_CONN`/`NET_DISCONN`/`NET_SEND`/
      `NET_SERVER` (`cmd_net.c`, on the `net_link.c` socket engine: up to 4
      concurrent TCP/UDP links, doc-numbered 0-3), `NET_PING`/`NET_DNS`/
      `NET_SNTP`/`NET_SNTPCONF`/`NET_DHCPS`/`NET_DHCP` (`cmd_net_svc.c`),
      and `NET_DTMODE` transparent passthrough (`cmd_net_dtmode.c`, plus a
      passthrough hook added to `at_uart.c`). Byte-stuffing (Ch.1.4) is now
      actually wired up, for `NET_SEND`'s payload decode. SSL/TLS was
      recognized but rejected everywhere at this point (`net_link.h`) --
      implemented later, see **Phase 7**.
      Hardware-verified 2026-08-29 over COM7 against a real LAN (the board
      joined the same Wi-Fi AP as the test PC): `NET_CONN` (board→PC) and
      `NET_SERVER`+accept (PC→board) both round-tripped real TCP payloads
      end-to-end (`NET_CONN:DONE`, `NET_CLI_ACCEPTED`, `NET_RECV:IND` with
      correct byte-stuffing decode, `NET_CLI_CLOSED` on peer close);
      `NET_STATUS` matched live link state including the OS-assigned
      ephemeral local port; `NET_PING` against the test PC returned real
      RTTs; `NET_DNS` resolved a real hostname; `NET_DHCP` query matched
      actual station DHCP-client state; UDP receive + peer-learning
      verified (`NET_SERVER=1 udp` correctly captured the sender's ip:port
      into `NET_RECV:IND`). The UDP reply send back to that learned peer was
      flagged as not conclusively verified here (`NET_SEND` returned `OK`
      but the test PC's listening socket never observed it, suspected
      Windows Firewall) and `NET_DTMODE`'s "+++" guard-time escape timing
      hadn't been exercised against a real serial host either -- both
      closed out in **Phase 8**, along with `NET_DISCONN` (host-initiated
      close) and `NET_SNTPCONF`/`NET_DHCPS`/`NET_DHCP`(SoftAP), which this
      phase's own hardware pass never separately exercised.
- [x] **Phase 3** — HTTP client: `NET_HTTPSET`/`NET_HTTPHEADER`/
      `NET_HTTPGET`/`NET_HTTPPOST`/`NET_HTTPDOWNLOAD`/`NET_HTTPSTOP`
      (`cmd_http.c`, on `esp_http_client`); HTTP server: `NET_HTTPDSTART`/
      `NET_HTTPDSTOP`/`NET_HTTPDCONF` (`cmd_httpd.c`, on `esp_http_server`).
      Added a SPIFFS "storage" partition (`fs_store.c`) for
      `NET_HTTPDOWNLOAD`'s saved files, to be referenced by name from
      `NET_CONN=ssl`/`MQTT_CONF`/`AWS_CERT` once those phases land.
      GET/POST/DOWNLOAD run on a one-shot worker task (not inline in the AT
      dispatcher) so a slow request can't freeze the whole command
      interface -- `NET_HTTPSTOP` cooperatively cancels the in-flight one
      by flag, checked between reads (esp_http_client's ON_DATA event
      return value does *not* actually abort a transfer in this esp-idf
      version -- checked against its source before relying on it). HTTPS
      is fully supported despite the raw-socket SSL deferral (Phase 2):
      `esp_http_client` + the already-enabled public CA bundle
      (`esp_crt_bundle_attach`) handle TLS internally, a separate problem
      from net_link.c's hand-rolled socket engine.
      Hardware-verified 2026-08-29 over COM7, against both a local test
      server and the open internet: `NET_HTTPGET` against a local server
      round-tripped the exact doc-example response shape; `NET_HTTPGET`
      against a real HTTPS endpoint (`api.ipify.org`) completed a real TLS
      handshake and returned the device's actual public IP; `NET_HTTPSET`
      content-type + `NET_HTTPHEADER` ADD were both confirmed actually
      applied by inspecting the receiving server's logged headers;
      `NET_HTTPPOST` round-tripped a real JSON body with correct
      Content-Length; `NET_HTTPDOWNLOAD` fetched a real file and saved it
      to SPIFFS (confirmed via the source server's access log); `NET_HTTPD`
      server round-tripped Basic-auth (401 with no credentials, 200 with
      correct ones) serving live device info (MAC/version/Wi-Fi mode) to a
      `curl` request from the test PC; `NET_HTTPSTOP` correctly errored
      with "no request" when idle, and correctly cancelled a real in-flight
      slow request (`httpbin.org/delay/5`) -- confirmed the cancellation
      lands at the first read-loop check after headers arrive, not
      instantly, matching the documented cooperative-cancel limitation.
      Deferred: HTTPS *server* (`NET_HTTPDSTART`'s `ssl=1`) -- rejected for
      now. A different mechanism (`esp_https_server`) from Phase 2's
      `net_link.c`, so this gap didn't close when `NET_SERVER=ssl` did in
      Phase 7 -- still the last unimplemented item in the xlsx status
      tracker as of that phase, alongside `SYS_LSLEEP`/`SYS_ANTENNA`.
- [x] **Phase 4** — `MQTT_CONF`/`MQTT_ALPN`/`MQTT_CONN`/`MQTT_PUB`/
      `MQTT_SUB`/`MQTT_CLEAN` (`cmd_mqtt.c`, on esp-mqtt). The 4 profile
      slots (link_id 0-3) are a separate namespace from `net_link.c`'s
      socket links -- esp-mqtt owns its own connection/TLS/reconnect
      internally, so this file only tracks doc-level config/subscription
      state and maps esp-mqtt's events onto the Ch.7 notifications
      (`MQTT_CONN:IND`/`DONE`, `MQTT_DISCONN:IND` for an unsolicited loss
      only, `MQTT_RECV:IND`, `MQTT_CLEAN:DONE`). mqtts/wss get HTTPS-style
      TLS "for free" via `esp_crt_bundle_attach`, same reasoning as Phase
      3. Doc quirk handled specially: `MQTT_PUB`'s `<data>` example escapes
      an embedded quote by *doubling* it (`""` → literal `"`), a different
      convention from every other command's parser -- registered `raw` and
      hand-parsed instead of using the generic tokenizer.
      Hardware-verified 2026-08-29 over COM7 against a real public broker
      (`test.mosquitto.org:1883`, plain `mqtt`): `MQTT_CONF` set+query,
      `MQTT_CONN` completed a real broker handshake with correct async
      `MQTT_CONN:IND`+`DONE`; `MQTT_SUB` (+query) then a message published
      from the test PC via `paho-mqtt` arrived as a correctly-formatted
      `MQTT_RECV:IND`; `MQTT_PUB` with the doc's exact doubled-quote JSON
      example was received PC-side with the escaping correctly resolved to
      `{"power":"on"}`; `MQTT_CLEAN` round-tripped `OK`+`DONE` and
      correctly suppressed the unsolicited-loss notification (no spurious
      `MQTT_DISCONN:IND` after a host-requested clean, mirroring
      `WF_DISCONN`'s behavior).
      **Not exercised**: `mqtts`/`wss` (TLS) transport, `MQTT_ALPN`, and the
      mutual-TLS `cert_name` path -- no TLS-requiring public broker was
      used this round; the code path shares its TLS setup with the
      already-verified HTTPS client (Phase 3), so risk is believed low but
      unconfirmed.
- [x] **Phase 5** — `AWS_CLAIMCERT`/`AWS_PROVISION`/`AWS_CERT`/`AWS_CONN`/
      `AWS_DISC`/`AWS_PUB`/`AWS_SUB` (`cmd_aws.c`, on esp-mqtt + AWS IoT's
      own documented `$aws/certificates/create` and
      `$aws/provisioning-templates/.../provision` topics), done out of
      order after Phase 6 once the doc added AWS IoT's own **Fleet
      Provisioning by Claim** (2026-08-29 doc update) alongside the
      original `AT*M2M*AWS_PAIR` custom-pairing path. `AWS_PAIR` itself
      stays a stub -- its custom provisioning-service HTTP protocol is
      still never specified anywhere in the doc, unlike Fleet Provisioning
      by Claim which is a real, standard AWS service with a fully
      documented wire protocol -- so this phase implements *that* path
      completely rather than the still-unspecified one. **[2026-09-14]**
      formalized as a deprecation rather than a pending gap: `AWS_PAIR`
      (and `AWS_CERT`'s `op=FETCH`, which depends on it) is marked
      deprecated in `M2M-AT Command Set.docx` (now v1.3) in favor of Fleet
      Provisioning by Claim; the stub stays as-is, not removed.
      Doc gap handled by design decision: `AWS_PROVISION`'s signature
      (`<link_id> <template_name> [parameters_json]`) has no room for the
      AWS IoT account endpoint its claim-cert connection needs to reach,
      and that endpoint is a fixed per-account value (same for every
      device in a fleet), not something negotiated per-command. Stored via
      `AT*M2M*SYS_CONF` index 10 (a project-specific extension -- doc
      Appendix A explicitly reserves indexes 3-32 for exactly this) rather
      than inventing a new command or silently repurposing `MQTT_CONF`;
      `AWS_CONN` reads the same stored endpoint once a certificate exists.
      Ongoing `AWS_CONN` connections verify the broker via
      `esp_crt_bundle_attach()` (AWS's ATS roots are already in the public
      bundle enabled since Phase 3) rather than a separately-stored CA --
      only the one-time claim connection in `AWS_PROVISION` uses the CA
      file from `AWS_CLAIMCERT` explicitly. `AWS_PUB`'s doc-specified
      multi-step "OK, then a literal `>` prompt, then the raw payload as a
      *separate* write" shape (unlike every other command's single line)
      is implemented for real via a new `at_uart_read_raw()` primitive in
      `at_uart.c`, not simplified into an inline-payload shortcut.
      Hardware-verified 2026-08-29 as far as this environment allows --
      **no real AWS account/IoT Core setup was available**, so the actual
      certificate-issuance round trip and a genuine AWS IoT mTLS connection
      are unverified. What *was* verified end-to-end on real hardware: all
      guard-rail/error paths (`AWS_CLAIMCERT` rejects missing files;
      `AWS_CERT`/`AWS_CONN`/`AWS_PROVISION` correctly refuse when nothing
      is configured yet, with the exact doc-specified reason codes); real
      claim-cert files downloaded via `NET_HTTPDOWNLOAD` and accepted by
      `AWS_CLAIMCERT`; `SYS_CONF` index 10 (the endpoint extension) set and
      read back correctly; and, most importantly, `AWS_PROVISION` run
      against those real claim-cert files with a fake (unreachable)
      endpoint correctly progressed through every stage -- `OK` →
      `IND CONNECTING` → a real bounded MQTT/TLS connection attempt → a
      genuine 15s timeout → `ERROR 0 2` -- confirming the whole pipeline
      is wired correctly right up to the one boundary that genuinely
      requires the user's own AWS account to cross. Revisit once real AWS
      IoT Core credentials (a provisioning template + claim certificate)
      are available to complete the loop.
- [x] **Phase 6** — `OTA_CHECK`/`OTA_UPDATE` (`cmd_ota.c`, on
      `esp_https_ota`), done ahead of Phase 5 while its doc gap was open.
      Doc gap handled by design decision: `<url>` is vague about how
      `OTA_CHECK` learns the server's version without downloading the
      whole image -- rather than invent a separate manifest-file
      convention, `<url>` points directly at the firmware `.bin` and
      `esp_https_ota_get_img_desc()` reads just the embedded
      `esp_app_desc_t` header (a partial download) then aborts without
      writing to flash; the same `<url>` is reused verbatim for
      `OTA_UPDATE`, matching the doc's examples (identical URL passed to
      both). Version comparison is plain string-equality, not numeric/
      semver parsing (documented simplification). `OTA_UPDATE` downloads,
      flashes, and marks the new image bootable but does **not**
      auto-reboot -- the doc's text never mentions one, so the host is
      expected to follow up with `AT*M2M*SYS_RST` to actually switch over.
      Also added an explicit `PROJECT_VER` ("1.0.0") to the top-level
      `CMakeLists.txt` -- there's no git repo here for idf's default
      git-describe fallback, which was otherwise leaving `SYS_VER`/
      `OTA_CHECK` reporting just "1"; bump this by hand until there's a
      real release process.
      Hardware-verified 2026-08-29 with a genuine two-binary OTA cycle: a
      1.0.1-versioned build was served over local HTTP; `OTA_CHECK` against
      it correctly reported `1.0.0 1.0.1` (partial download only, confirmed
      by the small transfer before abort); `OTA_UPDATE` completed with
      `DONE`; `SYS_VER` immediately after confirmed *no* auto-reboot
      (still `1.0.0`); `AT*M2M*SYS_RST` then rebooted into the new
      image -- boot log showed `Loaded app from partition at offset
      0x220000` (the other OTA slot) and `App version: 1.0.1`, and
      `SYS_VER` afterward correctly reported `1.0.1`. Also verified
      `OTA_UPDATE`'s guard rails: refuses with reason 4 ("run OTA_CHECK
      first") for an unchecked URL.
- [x] **Phase 7** — the four items Phase 1/2 had deferred, closing out
      everything the xlsx status tracker (`doc/M2M-AT_Command
      Set_status.xlsx`) listed as "구현필요" except `SYS_LSLEEP`/
      `SYS_ANTENNA` and `NET_HTTPDSTART`'s `ssl=1` (see Phase 3 note).
      Done 2026-09-09, in order:
      - `WF_APMODE` (`cmd_wifi.c`): type 0 (init/erase, also calls
        `esp_wifi_restore()` to wipe esp_wifi's own flash-persisted STA/AP
        config)/1 (replay saved profile)/2 (explicit SoftAP + save),
        backed by the `m2m_sys` NVS namespace. Replaced the project-specific
        hardcoded boot auto-connect (`LGWiFi_F7CE`, added 2026-09-07) in
        `at_wifi_init()` -- that hardcode is gone.
      - `WF_WPS` (`cmd_wifi.c`): PBC/PIN via `esp_wifi_wps_*`
        (`wpa_supplicant` component, added to `PRIV_REQUIRES`).
        `WIFI_EVENT_STA_WPS_ER_*` wired into `wifi_event_handler()` --
        success flows into the existing `WF_CONN:DONE` path; failure/
        timeout/PBC-overlap and the module-generated PIN get
        project-specific `WF_WPS:DONE`/`WF_WPS:IND` notices, since the doc
        defines no async message of its own for WPS outcomes.
      - `WF_EAPCONF`/`WF_EAPCERT` (`cmd_wifi.c`, 802.1X/EAP-Enterprise):
        `esp_eap_client_*` API (`CONFIG_ESP_WIFI_ENTERPRISE_SUPPORT=y` was
        already on). `leap` is parsed but rejected with
        `AT_ERR_NOT_SUPPORTED` -- ESP-IDF's EAP client has no LEAP
        implementation at all. Certs load from the same SPIFFS store
        `NET_HTTPDOWNLOAD` populates (`fs_store.c`), identical pattern to
        `AWS_CLAIMCERT`.
      - `NET_CONN`/`NET_SERVER` `ssl` type (`net_link.c`/`cmd_net.c`): the
        shared select()-loop socket engine now carries SSL links via
        `esp_tls` instead of rejecting `NET_LINK_SSL` outright. Client
        connect (`connect_ssl()`) runs synchronously via
        `esp_tls_conn_new_sync()`, bounded like plain TCP's own connect
        timeout -- required by `NET_CONN`'s synchronous OK/ERROR contract
        (doc Ch.1.3 half-duplex); validates the server against the default
        public CA bundle (`esp_crt_bundle_attach`) unless `cert_name`
        supplies a client cert for mutual TLS. Server accept
        (`NET_SERVER=ssl`) wraps each accepted child via
        `esp_tls_server_session_init()` and drives the handshake to
        completion across several shared-task ticks with
        `esp_tls_server_session_continue_async()`, since blocking the one
        shared task would stall every other link -- retried every tick
        unconditionally rather than gated on `select()` readability, since
        a handshake can legitimately want to write. Both reuse the
        existing `NET_CONN:DONE`/`NET_RECV:IND`/`NET_CLI_ACCEPTED`/
        `NET_CLI_CLOSED` events (doc Ch.8.4: "notification flow is
        identical to the plain TCP case"); `cert_name` loads the same way
        as `WF_EAPCERT`. Needed `esp-tls` added to `PRIV_REQUIRES`
        (`esp_crt_bundle.h` was already reachable via `mbedtls`).
      Hardware-verified 2026-09-09 over COM7 to varying degrees:
      `WF_APMODE` and `WF_WPS` were verified against real `esp_wifi`
      behavior (query/erase round trip and a full type 2→1→0 SoftAP
      round trip for `WF_APMODE`; a real PBC session start/cancel for
      `WF_WPS`, plus argument validation for both). `WF_EAPCONF`/
      `WF_EAPCERT` and the SSL `NET_CONN`/`NET_SERVER` type were verified
      only for argument validation, state-machine errors, and (SSL) a
      real connect attempt failing cleanly on timeout -- **not** a full
      external round trip, in both cases because this environment lacked
      the needed infrastructure: no RADIUS server for EAP, and the only
      reachable Wi-Fi AP enforces client isolation (blocks direct
      device-to-device LAN traffic), which also blocked getting a test
      cert onto the board's SPIFFS via `NET_HTTPDOWNLOAD` from a local
      test server for the SSL round trip. Revisit both once that
      infrastructure (a RADIUS/Enterprise AP; any AP without client
      isolation, or a real publicly-trusted TLS endpoint) is available.
- [x] **Phase 8** — re-verification pass over the xlsx status tracker's
      remaining "검증필요" items (Phase 1/2 hardware gaps that Phase 7 didn't
      touch), done 2026-09-12 over COM7 against two different Wi-Fi
      networks (an isolated mobile hotspot for internet-only checks, then
      `kangaps25` -- a normal home AP without client isolation -- for
      everything needing a real external peer). No code changes; this
      phase only closes out verification gaps and updates
      `doc/M2M-AT_Command Set_status.xlsx` accordingly.
      Confirmed on real hardware: `NET_DISCONN` (host-initiated close,
      checked via `NET_STATUS` before/after against a real external TCP
      peer); `NET_SEND` UDP round-trip (against a public TCP/UDP echo
      service, `tcpbin.com:4242`, sidestepping the earlier suspected
      Windows-Firewall-on-the-test-PC issue entirely -- succeeded cleanly,
      supporting the firewall theory over a code defect); `NET_DTMODE`'s
      "+++" guard-time escape, for the first time with a real open link and
      real timing (raw bytes relayed through passthrough and echoed back,
      then escaped via >=20ms silence / `+++` / >=20ms silence exactly per
      doc Ch.8.5, landing straight back in AT command mode); `NET_SNTPCONF`
      (server/offset set+query persistence); `NET_DHCPS` (SoftAP lease pool
      set+query) and `NET_DHCP` mode=1 (SoftAP DHCP server start/stop, the
      one mode Phase 2 hadn't separately exercised); `NET_HTTPHEADER`'s
      `DEL`/`CLR` (via `httpbin.org/headers` echo, isolating this from any
      PC-hosted receiver); `NET_HTTPDSTOP` (start -> reject a second start
      while running -> stop -> reject a second stop while idle -> start
      again successfully, proving the port is actually freed).
      Minor gap found in passing: `AT*M2M*NET_DTMODE=1 <link_id>` returns
      `OK` even when `<link_id>` was never opened via `NET_CONN` --
      `cmd_net_dtmode.c` only range-checks the link id, never checks it's
      actually connected, so passthrough silently drops everything on a
      bad link_id instead of erroring. Not fixed this phase, not separately
      tracked (low severity, host-error-only).
      **Still open, tracked as Notion issues** (not closed by this phase):
      `NET_SNTP` itself times out on both networks tested even though DNS
      resolves fine and arbitrary-port TCP/UDP work on the same link --
      suspected NTP (UDP/123) port filtering on the specific networks used,
      not a code defect, but unconfirmed without a third network to try.
      **Resolved 2026-09-26**, and the suspicion above was wrong: the real
      cause was `cmd_net_svc.c`'s `ensure_sntp_configured()` forcing
      `esp_sntp_config_t.wait_for_sync = false`. ESP-IDF's
      `esp_netif_sntp_init()` only allocates the sync-completion semaphore
      when that flag is true; with it false, `esp_netif_sntp_sync_wait()`
      (called right after, in `cmd_net_sntp()`) finds that semaphore NULL
      and returns `ESP_ERR_INVALID_STATE` *immediately*, on every call, on
      any network -- this command could never have succeeded since the day
      it was written. Also separately raised `CONFIG_LWIP_SNTP_MAX_SERVERS`
      1 -> 3 (the code always configures 3 servers: the primary +
      `time.nist.gov` + `time.windows.com`; the mismatch was logging its own
      init error but wasn't the actual blocker). Hardware-verified after
      both fixes on a real network (a mobile hotspot, reproduced twice from
      a clean boot): `NET_SNTP:IND` reported the correct wall-clock time,
      `NET_SNTP:DONE` followed. `MQTT_CONN`'s `mqtts` transport fails TLS handshake (reason 3)
      against `test.mosquitto.org:8883` even with DNS/arbitrary-TCP/UDP and
      HTTPS (same `esp_crt_bundle_attach` mechanism) all working on the same
      run, so not a general connectivity or clock problem -- needs a closer
      look at esp-mqtt's TLS config specifically.
      Process note: hit the USB Serial/JTAG auto-reset gotcha twice this
      session (rejoining Wi-Fi disappeared after two separate confusing
      STA-disconnect episodes) before remembering its cause -- every fresh
      `pyserial.Serial(...)` open on COM7 toggles DTR/RTS and reboots the
      board, so a multi-command test sequence has to run inside one
      continuously-open serial connection, never split across separate
      script invocations.

- [x] **Phase 9** — MQTT-over-TLS bug fixes and end-to-end verification
      against a private test broker, done 2026-09-12 once a peer session
      stood up a Docker Mosquitto broker (mqtts/mTLS/wss on
      192.168.200.103) specifically to unblock this.
      Two real bugs found and fixed along the way, neither previously
      caught because nobody had a working local build toolchain until this
      session (see the `sdkconfig` fix below):
      `AT_MAX_PARAMS` in `at_parser.h` was `8`, silently truncating
      `MQTT_CONF`'s documented 9th parameter (`cert_name`) on every call
      that supplied one -- raised to 16, which also covers `WF_EAPCERT`'s
      up to six `<type> <value>` pairs (12 tokens) that had the same latent
      risk. `cmd_mqtt.c` and `net_link.c`'s SSL/TLS paths could only verify
      a server certificate against the public ESP-IDF CA bundle --
      `cert_name` was wired in only as a *client* cert for mutual TLS,
      never as a custom CA for verifying the *server*, making TLS against
      any broker with a private CA structurally impossible (and in
      `net_link.c`, supplying `cert_name` for mTLS skipped server
      verification entirely, a real hole). Fixed both: `cert_name`'s file
      now also populates `broker.verification.certificate` (mqtt) /
      `cacert_buf` (net_link), with client-cert fields populated only when
      the same file also contains a `PRIVATE KEY` block -- so one uploaded
      file can serve as CA-only, client-cert-only, or both concatenated.
      `cmd_mqtt.c`'s cert scratch buffer also raised 4096 -> 8192 bytes to
      fit a combined CA+cert+key bundle.
      Also fixed, unrelated to the TLS work but discovered because it blocked
      building at all: `sdkconfig` had `CONFIG_PARTITION_TABLE_SINGLE_APP=y`
      (default 1MB) instead of `CONFIG_PARTITION_TABLE_CUSTOM=y` pointing at
      this project's own `partitions.csv` (proper two-OTA-slot 1536K
      layout), and `CONFIG_ESPTOOLPY_FLASHSIZE` was `2MB` when the board is
      physically 4MB (`esptool flash_id`, matching `partitions.csv`'s own
      "ported from ESP32_N4" comment) -- without both fixes the firmware
      doesn't fit and the build fails outright.
      With those fixes, confirmed on real hardware against the Docker
      broker (after also regenerating its `server.crt` to add an
      `IP:192.168.200.103` SAN, since the original only covered
      `mqtt-test-broker`/`localhost`/`127.0.0.1`): `MQTT_CONN` succeeds over
      **mqtts** (8883, CA-only), **mTLS** (8884, `cert_name` = CA+client
      cert+key concatenated), and **wss** (9001); `MQTT_ALPN` confirmed the
      extension doesn't break the handshake; a full `MQTT_SUB` ->
      `MQTT_PUB` -> `MQTT_RECV:IND` round trip verified over the mqtts
      link. `doc/M2M-AT_Command Set_status.xlsx` updated accordingly for
      `MQTT_ALPN`/`MQTT_CONN` (command table and Ch.7 notification table).
      `test.mosquitto.org:8883`'s TLS handshake failure noted in Phase 8
      remains open and unrelated -- that broker uses a publicly-trusted CA,
      so the bugs fixed here don't explain it.
      Also confirmed, contradicting the xlsx's still-stale "완전 미구현"
      status: `WF_EAPCONF`/`WF_EAPCERT`/`WF_WPS` and `NET_CONN`/
      `NET_SERVER`'s `ssl` type are actually implemented in code (commits
      `669c01e`, `d6e9ec7`, `8cdee39`) and registered in the dispatch
      table -- not re-verified on hardware this phase, but the xlsx's
      "not implemented" text for these four should not be trusted without
      rechecking the code.

- [x] **Phase 10** — AWS IoT Fleet Provisioning by Claim, verified
      end-to-end against a real AWS account, done 2026-09-13 once a peer
      session stood up real AWS IoT Core test infra (account
      `918734735576`, ap-southeast-2 -- a claim cert scoped to
      `$aws/certificates/create/*` and one provisioning template's topics,
      the template itself, and its provisioning role/policies; see
      `C:\Dev\PRJ\85.AWS\IoT-Core-Test\aws-resources.md`).
      Three real bugs found and fixed in `cmd_aws.c`'s `AWS_PROVISION`
      path, none caught before because nobody had exercised a real
      successful provisioning round trip: AWS's certificate-creation
      response is a 3.5KB+ JSON blob (cert+key+token) that arrives split
      across multiple `MQTT_EVENT_DATA` fragments, but
      `provision_event_handler` only ever captured the first fragment and
      signalled done immediately -- handing the worker truncated,
      unparseable JSON, misreported to the host as "certificate request
      rejected" (ERROR 3) on every attempt. Fixed with proper fragment
      reassembly (`current_data_offset`/`total_data_len`) and the payload
      buffer raised 2200 -> 6144. That larger buffer lives in a stack-local
      struct inside the `provision_worker` task, which once big enough blew
      the task's 8192-byte stack (`Guru Meditation Error: Stack protection
      fault`) -- task stack raised 8192 -> 16384. And
      `certificateOwnershipToken` (an opaque encrypted blob, observed 464
      characters for a 2048-bit RSA cert) was silently truncated by a
      300-byte buffer, so a corrupted token got sent to AWS's registration
      step and was correctly rejected -- misread as a template/permissions
      problem (ERROR 4) rather than truncation. Buffer raised 300 -> 600.
      Found by replicating the exact MQTT topic exchange directly from a
      PC with `paho-mqtt` (bypassing the ESP32 entirely, same claim cert)
      to confirm AWS's side was fine before concluding the bug was
      firmware-side.
      Confirmed on real hardware after all three fixes: `AWS_PROVISION`
      completes (`DONE 0 "esp32-<SerialNumber>"`), `AWS_CERT` reflects the
      new identity, `AWS_CONN` connects with the freshly-provisioned device
      certificate (verified via the public CA bundle against AWS's ATS
      root, same as Phase 3/4), and `AWS_PUB`/`AWS_SUB` round-trip a real
      message via `AWS_MSG:DONE`. `doc/M2M-AT_Command Set_status.xlsx`
      updated accordingly (`AWS_PROVISION`/`AWS_CERT`/`AWS_CONN`/
      `AWS_DISC`/`AWS_PUB`/`AWS_SUB` rows and their Ch.7 notification
      counterparts, all 검증필요 -> 검증완료).
      Process note: getting the claim certificate/key onto the board
      needed `NET_HTTPDOWNLOAD` from a locally-served HTTP directory --
      copying real AWS credentials into a self-served folder was correctly
      blocked by the session's own permission policy ("Credential
      Leakage"); the user ran that server themselves instead.
- [x] **Phase 11** — `BLE_PROV` (doc Ch.3.5, Rev 1.5-1.7), BLE Wi-Fi
      provisioning, done 2026-09-26. A Query+Set window that lets an
      end-user's phone app (Espressif BLE Provisioning-compatible) hand
      Wi-Fi credentials straight to the module without going through the
      host. `cmd_ble_prov.c` is a thin wrapper over ESP-IDF's
      `wifi_provisioning` + `protocomm` (`wifi_prov_scheme_ble`, NimBLE,
      Security1) rather than a custom protocol -- see
      `doc/M2M BT Provisioning Architecture Review.docx` for why (reuse
      Espressif's own app while keeping a path open to other Wi-Fi chip
      vendors by treating the wire protocol as the spec). Notifications:
      `IND CONNECTED`/`CRED_RECEIVED`/`CRED_FAIL`, `DONE`, `ERROR 1`
      (window timed out; granted one 10s grace period if the STA has
      already associated and is only waiting on DHCP). On `DONE` the
      connection is saved as the `WF_APMODE=1` profile
      (`at_wifi_persist_apmode_sta()`) so it survives a reboot; the window
      itself never persists across a reset.
      Hardware findings on COM7: calling `wifi_prov_mgr_deinit()` from the
      manager's own `WIFI_PROV_END` callback self-deadlocks on
      `prov_ctx_lock` (moved to a system-event-loop handler, as Espressif's
      example does); and fully tearing down the BLE controller on stop makes
      the next session crash inside Espressif's closed controller blob
      (`r_lld_env_init`, NULL function pointer). The controller is now kept
      alive across stop (`wifi_prov_mgr_keep_ble_on(1)`), which removes the
      crash but leaves a **known limitation: one session per boot** -- a
      further `BLE_PROV=1` fails cleanly with `ERROR 0` until `SYS_RST`
      (documented in Rev 1.7).
      Fitting it in: the image grew to 0x192490, so `partitions.csv`'s
      `ota_0`/`ota_1` went 1536K -> 1664K (~148KB of the 4MB flash left).
      Free heap was too low for `wifi_provisioning`+NimBLE to init, so five
      2200-byte PEM scratch statics were collapsed into one shared
      `g_at_pem_scratch` (`at_pem_scratch.c/h`, ~8.8KB .bss) for call sites
      whose callee copies the data (esp_tls, `httpd_ssl_start`, PAC file);
      cert/key buffers that esp-mqtt and wpa_supplicant keep as raw
      pointers (`cmd_aws.c`/`cmd_mqtt.c`/`cmd_wifi.c`) are instead
      heap-allocated to the file's actual size and freed with their client.
      Still open: the xlsx marks `BLE_PROV` 검증필요 because no phone-app
      run through `DONE` + reboot auto-reconnect is logged yet; the
      proof-of-possession is a fixed placeholder string (`esp32c3pop`) and
      must become a per-device secret before production; `IND CONNECTED`
      fires on `WIFI_PROV_START` (window up), not on an actual phone
      connecting, since `wifi_prov_mgr` exposes no such event.
- [x] **Phase 12** — EN 18031-1 (RED cybersecurity) Phase A, done
      2026-09-27 (plan and status: `doc/EN18031-1_To-Do.xlsx`; doc Rev 1.8).
      Web login moved into `web_auth.c`: only a salted
      PBKDF2-HMAC-SHA256 hash of the password is stored (10,000 iterations,
      ~0.4 s per check; an older plaintext `httpd_pw` is converted on first
      boot); a password policy (8-64 printable characters, letters and
      digits, not the id or the default) applies to both the web and
      `NET_HTTPDCONF` (new reason 1); the factory default admin/admin only
      opens `POST /api/password` until changed (every other route answers
      403, the WebUI shows a forced change screen); 5 failed logins lock web
      login for 60 s, doubling per further lockout up to 1 h, with the round
      counter kept in NVS so a reboot doesn't reset it; sessions expire
      after 10 min idle / 12 h. The WebUI's About tab gained a password
      change form. `NET_HTTPDCONF`, `WF_APMODE` and `WF_EAPCONF` Query
      responses mask stored passwords as `********`. New Kconfig options:
      `AT_MODEM_HTTPD_MODE` (HTTP or HTTPS / HTTP only / HTTPS only;
      `NET_HTTPDSTART` reason 4 for a disabled transport, and an HTTPS-only
      build never falls back to plain HTTP at boot) and
      `AT_MODEM_SOFTAP_ALLOW_OPEN` (off refuses an open SoftAP); `POST /ota`
      is refused unless the server runs over HTTPS. The BLE provisioning PoP
      is now per device -- 12 characters from the hardware RNG on first
      boot, stored in NVS -- readable/settable with the new
      `AT*M2M*BLE_POP`. The unused `AT_MODEM_TCP_PORT` Kconfig entry was
      removed. Verified on COM7: policy accept/reject, masking, persistence
      across reboot, and the lockout (60 s, still locked after a reboot,
      120 s second round, cleared by an AT credential reset -- exercised via
      a temporary test command calling `web_auth` directly, since removed).
      Not yet verified: the web (HTTP) side -- forced change screen,
      `/api/password`, the 429 response and HTTPS-only `/ota` -- because the
      PC was on a client-isolating hotspot and couldn't reach the board.
      App partition now has ~64KB (4%) left.
      2026-10-04: the web side was then verified with curl from a PC on
      the same (non-isolating) AP -- forced change (403 on every other route
      until changed, policy rejections, old default refused afterwards),
      `/api/password` with wrong/right current password, the 429 lockout
      with `Retry-After` and its 60 s release, idle session expiry (alive at
      9.5 min, expired at 10.5 min), and `/ota` refused over HTTP but past
      the HTTPS gate over HTTPS (`Secure` cookie). WebUI screenshots of the
      forced change screen and the About form are still to be taken.
      Also on 2026-10-04: the HTTPS-only and HTTP-only builds (reason 4 for
      the disabled transport, boot auto-start never falling back to a
      disallowed transport), `AT_MODEM_SOFTAP_ALLOW_OPEN=n` (open
      `WF_APSTART` refused), and the old plaintext `httpd_pw` conversion
      were hardware-verified. Found while checking the conversion: NVS only
      marks the old plaintext entry erased, so its bytes stay in flash until
      that page is garbage-collected (a full `SYS_FACTORY` erase does remove
      them) -- only NVS/flash encryption (Phase B) fully covers this.
      Wi-Fi join retry (2026-10-04): after a hard reset or power loss while
      associated, some APs (seen with a phone hotspot) still hold the old
      association and reject the next auth (AUTH_FAIL, then CONNECTION_FAIL
      for a few seconds). Nothing retried, so a `WF_APMODE` auto-reconnect
      stayed offline until the host acted. `cmd_wifi.c` now retries an
      auth-type failure up to 3 times, 3 s apart (esp_timer), reporting
      `WF_DISCONN:DONE` only for the last failure; `WF_DISCONN` and any new
      connect cancel it. `SYS_RST` was never affected (`esp_restart()`
      deauthenticates first). Verified: recovery on every hard reset, both
      via `WF_CONN` and `WF_APMODE`; wrong password / unknown SSID still
      reported at once; `WF_DISCONN` cancels a pending retry. Doc Rev 1.9.
      2026-10-04 (to-do B-06, option c): `partitions.csv` shrank `storage`
      512K -> 256K (it held ~4.7KB) and grew `ota_0`/`ota_1` 1664K -> 1792K
      (ota_0 at 0x60000, ota_1 at 0x220000; the last 128K of flash stays
      unused as a reserve), so the app partition has ~192KB (11%) free. The
      partition table can't change over OTA: existing boards need a USB
      reflash (ota_0 is now at 0x60000), and the moved SPIFFS starts empty.
      Doc Rev 1.9 states the ~228KB file system capacity under
      `NET_HTTPDOWNLOAD`. Flashed and booted on COM7.
- [x] **Phase 13** — EN 18031-1 Phase C, done 2026-10-04 (to-do C-01..C-05;
      doc Rev 1.10). TLS (`sdkconfig`): TLS 1.3 on; RSA and static-ECDH key
      exchange, the TLS 1.3 pure-PSK mode and renegotiation off, so every
      TLS client and server only does forward-secret key exchange. Key
      strength: `fs_store_check_key_strength()` refuses certificates/keys
      below RSA-2048 / EC P-256 on web upload (400) and `NET_HTTPDOWNLOAD`
      (reason 5; the file is not kept). DoS: the web server keeps at most
      `AT_MODEM_HTTPD_MAX_SOCKETS` (3) connections; the HTTPS server's
      handshake / receive timeouts are 2.5 s / 3 s, because
      `esp_https_server` does each handshake synchronously in its one task
      and a silent client stalled everyone for ~15 s (now ~3 s per idle
      connection, recovering as soon as it goes away -- a residual risk to
      declare); `NET_SERVER` ssl closes a client that hasn't finished its
      handshake in 10 s and checks for a free slot before allocating TLS.
      Input checks: storage file names are 1-30 characters of
      `[A-Za-z0-9._-]` not starting with `.` (enforced in `fs_store_path()`),
      SSID/passphrase, MQTT and Enterprise fields are refused instead of
      truncated, and malformed static IPs are refused. Enterprise Wi-Fi now
      verifies the RADIUS server against the public CA bundle when no CA is
      staged (`AT_MODEM_EAP_ALLOW_NO_CA` restores the old behaviour); all
      other TLS clients already verified the server. App partition: ~134KB
      (7%) free. Verified on COM7 / kangaps25: TLS 1.3 and refusal of
      non-forward-secret suites (server and client), weak-key rejection,
      connection floods, the NET_SERVER handshake timeout, all AT and web
      input checks, and a 1.7MB HTTPS `/ota` with the shorter timeout. Not
      verified on hardware: the Enterprise CA-bundle fallback (no
      Enterprise AP in range).
- [x] **Phase 14** — EN 18031-1 to-do B-03, NVS encryption, done 2026-10-04
      (doc Rev 1.11). `CONFIG_NVS_ENCRYPTION` with the HMAC scheme
      (`nvs_sec_provider`, added to `main`'s requirements since the project
      uses `MINIMAL_BUILD`): on first boot the firmware writes a random key
      into eFuse KEY5 (purpose HMAC_UP, read-protected -- irreversible, one
      of six key blocks) and derives the NVS XTS-AES keys from it, so no
      Flash encryption or `nvs_keys` partition is needed. `fs_store` now
      keeps any file holding a private key (PEM `PRIVATE KEY`, or a
      `.key/.p12/.pfx/.pac` name) in encrypted NVS (namespace `m2m_files`,
      at most 8 KB each) and everything else in SPIFFS, behind one API
      (`fs_store_read/read_alloc/write/remove`) that every caller now uses
      instead of `fopen()`; web uploads and `NET_HTTPDOWNLOAD` files up to
      16 KB are buffered in RAM so a key never touches SPIFFS. Keys an older
      firmware left in SPIFFS are moved at boot and the storage partition is
      reformatted (SPIFFS keeps deleted pages). Updating from an older
      firmware clears NVS once (plaintext NVS can't be read encrypted); a
      factory reset now also deletes stored keys. Verified on COM7 with
      flash dumps: the old firmware showed the Wi-Fi SSID/passphrase in
      plaintext NVS and private-key PEM headers in storage; afterwards NVS
      shows none of them (not even namespace names) and storage holds no
      key. HTTPS and `NET_SERVER` ssl run with keys read from NVS; an 8 KB+
      key file is refused (413). Limits: XTS-AES gives confidentiality, not
      tamper detection, and without Secure Boot (B-01) a reflashed firmware
      could derive the same keys through the HMAC peripheral.
- [x] **Phase 15** — EN 18031-1 to-do D-01, SBOM and CVE review, done
      2026-10-04. `doc/SBOM/esp32_c3.spdx` (SPDX 2.2 tag-value) and
      `esp32_c3.spdx.json`, generated by Espressif's `esp-idf-sbom` 1.4.0
      from `build/project_description.json` with `--rem-config --rem-unused`
      (only what is linked into the image: 76 packages -- ESP-IDF 5.5.4,
      mbedTLS 3.6.5, lwIP 2.2.0, FreeRTOS 10.5.1, wpa_supplicant 2.10,
      NimBLE 1.6.0, cJSON 1.7.19, ...). `esp-idf-sbom check` against NVD
      (`doc/SBOM/cve_check_2026-10-04.json`) lists 20 CVEs for these
      versions; `doc/SBOM/EN18031-1_SBOM_CVE.xlsx` assesses each for this
      firmware: 2 apply (mbedTLS CVE-2026-34874, a crash on a malicious
      peer certificate; lwIP DHCP server CVE-2026-45160, SoftAP mode only),
      6 mbedTLS ones are conditional or unclear, 12 don't apply (ESP-TEE,
      WebSocket, protocomm Security2, cJSON_Utils, LLVM-only, ...). ESP-IDF
      v5.5.5 (mbedTLS 3.6.6 plus the DHCP server fix) resolves the ones
      that matter -- recommended as the next step. Regenerate the SBOM and
      re-run the check after every ESP-IDF update or release.

- [x] **Phase 16** — OTH-AT: build-time command set choice, 2026-10-05.
      Kconfig `AT_MODEM_CMDSET`; the tag in the parser, replies and events
      follows it (`include/at_cmdset.h`), one dispatch table per set,
      unknown command 99 (M2M) / 9 (OTH). OTH build ~23% app space free
      vs 6% for M2M.
- [x] **Phase 17** — OTH-AT Basic + Wi-Fi (Essentials Ch.2/3,
      `cmd_oth_basic.c`, `cmd_oth_wifi.c`): station, SoftAP, WPS, EAP,
      AUCONMODE/SMODE, events ASSOCIATED/DISASSOCIATED/IPALLOCATED/
      IPRELEASED/INITSCAN/DEVICEREADY. IBSS, WDS, P2P, 11g/11n-only and
      5 GHz modes are not supported by ESP32-C3; WEP refused.
- [x] **Phase 18** — OTH-AT TCP/IP + SSL (Ch.4/5): `oth_sock.c`, a
      BSD-style socket engine (descriptors TCP 0-2, UDP 3-5, SSL 6, a
      listening socket keeps its descriptor for all clients, async
      CONNECT), data mode with DATA_INTERVAL aggregation and a 500 ms
      "+++" guard. Fixed on the way (also M2M): LF bytes inside a command
      line were dropped, corrupting payloads.
- [x] **Phase 19** — OTH-AT services (Ch.6) + MIB/SETMIB + FWUPGRADE: HTTP
      client with streamed HTTPBODY, HTTP_DOWNLOAD, HTTPD_*, SNTP*, FTPC_*,
      OTA_VERCHECK/REQUEST, XMODEM firmware download into ota_0/ota_1.
      DDNS/UPnP/LPD out of scope.
- [x] **Phase 20** — OTH-AT MQTT volume (`cmd_oth_mqtt.c`): one client with
      indexed settings, auto-subscribe, persistence 0/1/2, MQTT_CERT; the
      web MQTT screen drives it in the OTH build. Verified against
      broker.emqx.io (1883/8883).
- [x] **Phase 21** — OTH-AT AWS volume (`cmd_oth_aws.c`): pairing package
      `aws_conf.json` + `aws_claim.pem`, Fleet Provisioning by Claim as
      "authenticate", topics `<thing>/up|down/<apiNo>`. Verified on the
      AWS test account (provisioning, CONNECT, SEND, reboot reconnect);
      AWS_RECV not yet verified. CoAP volume not implemented (decision
      2026-10-05). Replaced by Phase 22.
- [x] **Phase 22** — OTH-AT AWS volume rebuilt as an OTH Platform client
      (2026-10-06; the OTH build serves only this platform). SoftAP pairing
      server `oth_pairing.c` (TCP 47000, "GEN2" frames, DP0100-0400,
      optional AES-128 session) stores root CA / auth server / endpoint /
      port / region and joins the home AP, then closes the SoftAP and keeps
      the station profile. `cmd_oth_aws.c`: token + device certificate from
      the authentication server (`/register/token|auth`), root CA download,
      MQTT topics `<root>/{Conn|Event|Control|Lwt}/<MIB19>/<MIB18>/<clientId>`
      with the header/values envelope, A100 on every connection, A102 as
      LWT; A502/A511/A521/A531 handled in the module, A001 (renewal) and
      A101 (deregistration) acted on and passed to the host; 60 s retry.
      `oth_fota.c`: module FOTA (plain or AES-256-CBC, SHA-256, image ID
      check) and MCU firmware staged in the inactive OTA slot and relayed
      with MOTA_*. New commands AWS_SET, MCU_READY, MOTA_START/READY/DATA/
      DATA_END; Kconfig `AT_MODEM_OTH_TOPIC_ROOT`, `AT_MODEM_OTH_PAIRING_PORT`.
      Board-verified 2026-10-06 against a LAN mock authentication server and
      broker.emqx.io: token/certificate/key, stored-credential reconnect
      without the server, topics + envelope, A100 (versionChangeW/M), A102
      LWT, AWS_SEND apiGroup, AWS_RECV (attributes / flat values), foreign
      deviceId dropped, A502->A500, A511 encrypted FOTA (wrong hash refused,
      right hash installed + rebooted), A521 + MOTA relay (CRC matches),
      A001 renewal, DISCONNECT on link loss + rejoin, boot auto-connect.
      Not yet verified: pairing with the app, A101 (erases NV memory), the
      real servers.

Explicitly out of scope (no corresponding chapter in the M2M-AT Command Set
doc, or excluded by decision): Wi-Fi Direct/P2P, CoAP, oneM2M, UPnP, DDNS,
LPD, FTP, the mobile-pairing server, the MCU-firmware (MOTA) relay, and the
Binary UART Protocol (a separate, unread doc).

## Release naming (2026-09-26, M2M_SW Release Naming Guide v2.0)

Three new design documents (`doc/M2M-AT Command Set v2.0.docx`,
`doc/M2M_SW Release Naming Guide v2.0.docx`, `doc/M2M_Code Register.xlsx`)
define a release/binary filename convention and a matching set of
compile-time identity constants -- implemented here:

- **`main/Kconfig.projbuild`** ("M2M Release Naming" menu, `idf.py
  menuconfig`): board code (MA0 vendor-standard module by default, per the
  code register), customer/contract code (AC0 default -- no specific
  customer), CONFIG segment (boot-notification PWRON, filesystem FS, security
  SEC), all backed by codes registered in `doc/M2M_Code Register.xlsx`. CHIP/
  APP/CMD/IF are fixed constants for now (this tree only ever builds one
  chip/firmware-type/AT-dialect/transport combination) but are still real
  Kconfig-visible values, not hardcoded literals, so a second dispatch table
  or chip port later has a real switch to flip.
- **`components/at_modem/m2m_version.h`/`m2m_image_id.c`**: `M2M_FW_VERSION`
  (== `PROJECT_VER`, top-level `CMakeLists.txt` — now `"01.00"`, the first
  release under this scheme per the guide's own restart-numbering advice),
  `M2M_FW_CUSTOMER` (e.g. `"AC0"`), and `M2M_FW_IMAGE_ID` (e.g.
  `"EC3-MA0-N04-40M_MM_AC0"`, `_OT_` in the OTH-AT build), embedded via the ESP-IDF-reserved
  `.rodata_custom_desc` section, right after `esp_app_desc_t`).
- **`AT*M2M*SYS_VER`** now reports a third field, `<customer_code>` (doc
  v2.0/Rev 1.4): `*M2M*SYS_VER:OK 01.00 2026-09-26-13:00:58 AC0`.
  Hardware-verified over COM7.
- **`*M2M*DEVICEREADY`** (added unconditionally during the 2026-09-06 audit)
  is now gated behind `CONFIG_M2M_PWRON_NOTIFY` (off by default, matching
  both this project's actual behavior before today and the doc's own
  documented PWRON=0 default) -- the concrete example of "compile in only
  what a given release configuration actually needs." Verified off by
  default over COM7 (no `DEVICEREADY` line after a fresh boot).
- **`AT*M2M*OTA_UPDATE` reason 5** ("downloaded image ID does not match the
  installed image"): `cmd_ota.c`'s `OTA_CHECK` phase now also reads the
  target OTA partition's own `M2M_FW_IMAGE_ID` (via a raw
  `esp_partition_read()` at the same offset `esp_ota_get_partition_
  description()` uses for `esp_app_desc_t`, one struct further) during its
  existing partial-download-then-abort flow -- nothing new gets committed to
  flash by this check. `OTA_UPDATE` refuses with reason 5 if it doesn't
  match. Build and boot verified over COM7 (`SYS_VER` unaffected, no crash);
  a live network OTA round-trip trying an actually-mismatched image was
  **not** exercised this session -- blocked by the same AP-isolation issue
  open elsewhere in this README's history, not by this feature. The offset
  math itself was checked directly against ESP-IDF's own
  `esp_ota_get_partition_description()` source, not guessed.
- **`tools/make_release.py`**: run after `idf.py build` to package
  `build/`'s output into `build/release/<NAME>/` per the guide's section 5
  layout (`<NAME>_factory.bin` via `esptool merge_bin`, `<NAME>_ota.bin`,
  the individual `bin/*` pieces, `SHA256SUMS.txt`) -- reads
  `project_description.json`/`config/sdkconfig.json`/`flasher_args.json`
  (all generated by the build itself) rather than re-deriving any value by
  hand, so nothing here needs to be kept in sync separately from the Kconfig
  choices above. Verified: produced
  `M2M_EC3-MA0-N04-40M_AT-MM-USB_V01.00_AC0_0SN_260926[_factory|_ota].bin`,
  matches the guide's own Appendix A filename-validation regex exactly.
  Still manual: `ReleaseNote_<NAME>.pdf` (section 6.4's required-contents
  list) -- not generated.

## Port notes (ESP32-C3 vs. ESP32_N4/original ESP32)

- **AT transport defaults to the native USB Serial/JTAG controller**
  (`CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG=y`, on by default for this
  target) -- ESP32-C3 has a built-in USB Serial/JTAG peripheral, so the same
  USB cable used for flashing (COM7 on this PC) doubles as the AT command
  channel. **No second USB-serial adapter needed** -- hardware-verified
  2026-08-29 (`AT`/`ATE1`/`ATV` all round-tripped correctly over COM7).
  - Trade-off: the console's secondary output to USB Serial/JTAG had to be
    disabled (`CONFIG_ESP_CONSOLE_SECONDARY_NONE=y`) so `ESP_LOG` lines
    don't get interleaved into the AT byte stream. Debug logs now only go to
    the primary console, physical UART0 (GPIO20/21) -- wire a separate
    adapter there if logs are needed while also testing AT commands.
  - A brief burst of ROM/bootloader boot-log text can still land in the OS
    serial buffer right after a reset (before the app's `at_uart_init()`
    takes over the peripheral) -- harmless, just drain/ignore it before
    sending the first command.
- Falling back to a physical UART is still supported: set
  `CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG=n` in menuconfig to use **UART1,
  GPIO5=TX / GPIO4=RX** instead (GPIO16/17 from the original ESP32 target
  are unusable here -- wired internally to the embedded SPI flash,
  GPIO12-17). Same GPIO choice as the earlier `ESP32_C3_260809_ver_0000`
  port of this framework.
- Baud rate, 8N1, no flow control -- unchanged from ESP32_N4 (115200);
  n/a when using the native USB transport (it's a USB CDC, not a real UART).

## Board notes

- ESP32-C3 board; the single onboard USB port carries flashing, console,
  *and* (by default here) the AT command interface, all as COM7 on this PC.
- To use the physical-UART fallback instead, wire a second USB-serial
  adapter to GPIO4/GPIO5/GND.

## Project layout

```
├── CMakeLists.txt
├── partitions.csv             Dual-OTA partition table (needs 4MB flash)
├── components/at_modem/       AT modem component
│   ├── at_modem.c              init sequence: event queue, UART, Wi-Fi, socket engine
│   ├── at_uart.c/h             transport (UART1 or USB Serial/JTAG) + NET_DTMODE passthrough hook
│   ├── at_parser.c/h           line -> at_command_t, param tokenizer, Query-form helper
│   ├── at_dispatch.c/h         command name -> handler table
│   ├── at_event.c/h            async "*M2M*..." notification queue
│   ├── at_byte_stuffing.c/h    Ch.1.4 payload escape/unescape
│   ├── at_response.h           OK/ERROR/line reply helpers
│   ├── at_nvs_kv.c/h           shared NVS accessor (SYS_CONF/COUNTRY/UART/SNTP config)
│   ├── net_link.c/h            NET_* socket engine (up to 4 TCP/UDP links)
│   ├── cmd_special.c           AT/ATE/ATV
│   ├── cmd_sys.c                SYS_* Basic commands
│   ├── cmd_wifi.c               WF_* Wi-Fi commands + Wi-Fi driver bring-up
│   ├── cmd_net.c                NET_STATUS/CONN/DISCONN/SEND/SERVER
│   ├── cmd_net_svc.c            NET_PING/DNS/SNTP/SNTPCONF/DHCPS/DHCP
│   ├── cmd_net_dtmode.c         NET_DTMODE passthrough
│   ├── fs_store.c/h             SPIFFS file storage (NET_HTTPDOWNLOAD, later cert files)
│   ├── cmd_http.c               NET_HTTPSET/HEADER/GET/POST/DOWNLOAD/STOP (HTTP client)
│   ├── cmd_httpd.c              NET_HTTPDSTART/STOP/CONF (HTTP server)
│   ├── cmd_mqtt.c               MQTT_CONF/ALPN/CONN/PUB/SUB/CLEAN
│   ├── cmd_ota.c                OTA_CHECK/OTA_UPDATE
│   ├── cmd_ble_prov.c           BLE_PROV (wifi_provisioning over BLE)
│   ├── at_pem_scratch.c/h       shared PEM load buffer (callee-copies call sites only)
│   ├── web_auth.c/h             web login: password hash/policy, brute-force lockout, sessions
│   └── cmd_aws.c                AWS_PAIR(stub)/CLAIMCERT/PROVISION/CERT/CONN/DISC/PUB/SUB
├── tools/at_test.py           Host-side AT command test harness
├── main
│   ├── CMakeLists.txt
│   └── esp32_c3_main.c        nvs_flash_init() + at_modem_init()
└── README.md
```

For more information on structure and contents of ESP-IDF projects, please refer to Section [Build System](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html) of the ESP-IDF Programming Guide.

## Troubleshooting

* Program upload failure

  * Hardware connection is not correct: run `idf.py -p PORT monitor`, and reboot your board to see if there are any output logs.
  * The baud rate for downloading is too high: lower your baud rate in the `menuconfig` menu, and try again.

## Technical support and feedback

Please use the following feedback channels:

* For technical queries, go to the [esp32.com](https://esp32.com/) forum
* For a feature request or bug report, create a [GitHub issue](https://github.com/espressif/esp-idf/issues)

We will get back to you as soon as possible.
