#!/usr/bin/env python3
"""
Host-side test harness for the M2M-AT command modem.

By default (CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG=y) this talks directly
to the board's native USB Serial/JTAG port -- the SAME port used for
flashing (e.g. COM7), no extra wiring needed. Just point --port at that
port. Note: a brief burst of ROM/bootloader boot-log text can still be
sitting in the OS serial buffer right after a reset/flash -- harmless, just
ignore/drain it before trusting the first response.

If CONFIG_AT_MODEM_UART_USE_USB_SERIAL_JTAG is disabled in menuconfig, this
instead talks to the *physical AT command UART* (ESP32-C3 UART1, default
GPIO5=TX / GPIO4=RX, see components/at_modem/Kconfig) -- a second
USB-to-serial adapter wired to GPIO4/5/GND is then required, and --port
must point at that adapter instead.

Usage:
    python at_test.py --port COM7 --interactive
    python at_test.py --port COM7 --sequence boot

SEQUENCES is hand-written literal command strings with no abstraction layer
-- add entries here as each phase of
C:\\Users\\crowm\\.claude\\plans\\tingly-gathering-parasol.md lands new
commands.
"""
import argparse
import sys
import time

import serial

SEQUENCES = {
    # Phase 0: only AT/ATE/ATV exist.
    "boot": [
        "AT",
        "ATE1",
        "ATV",
    ],
    # WF_APMODE (doc Ch.3.1): query the saved profile, then init/erase it
    # (type 0 -- also wipes esp_wifi's own flash-persisted STA/AP profile
    # via esp_wifi_restore()), then query again to confirm it's gone.
    "wf_apmode": [
        "AT*M2M*WF_APMODE=?",
        "AT*M2M*WF_APMODE=0",
        "AT*M2M*WF_APMODE=?",
    ],
    # Functional check of type 2 (explicit SoftAP) + type 1 (replay saved
    # profile) + type 0 (erase) round trip -- not part of normal use, just
    # exercised once here to confirm the real esp_wifi calls behind each
    # type actually work on hardware, not only the NVS bookkeeping.
    # WF_WPS (doc Ch.3.4) argument validation + PBC start/cancel round trip.
    # No physical AP interaction here (that needs a real WPS button press),
    # just confirming the command surface itself: bad flag/pin rejected,
    # the WF_MODE=1/3 precondition enforced, then a real PBC session started
    # and immediately cancelled again to leave the radio idle.
    "wf_wps": [
        "AT*M2M*WF_MODE=0",
        "AT*M2M*WF_WPS=1",
        "AT*M2M*WF_MODE=1",
        "AT*M2M*WF_WPS=9",
        "AT*M2M*WF_WPS=2 123",
        "AT*M2M*WF_WPS=2 1234567a",
        "AT*M2M*WF_WPS=1",
        "AT*M2M*WF_WPS=0",
    ],
    # WF_EAPCONF/WF_EAPCERT (doc Ch.3.2) command-surface + validation check.
    # Full 802.1X negotiation needs a RADIUS server + Enterprise AP (see the
    # xlsx status tracker's own note) -- not available here, so this only
    # exercises what's testable without that infrastructure: get-before-set
    # state error, bad method/leap rejection, arg validation, a real set
    # round trip (which also calls esp_wifi_sta_enterprise_enable() for
    # real), a phase-2 method that needs no file, and the file-not-found
    # path for cert/key/PAC types (no cert files exist on this device yet).
    "wf_eap": [
        "AT*M2M*WF_EAPCONF=0 peap",
        "AT*M2M*WF_EAPCONF=1 leap user pass",
        "AT*M2M*WF_EAPCONF=1",
        "AT*M2M*WF_EAPCONF=1 peap user1 secret123",
        "AT*M2M*WF_EAPCONF=0 peap",
        "AT*M2M*WF_EAPCERT=0 MSCHAPV2",
        "AT*M2M*WF_EAPCERT=0 BOGUS",
        "AT*M2M*WF_EAPCERT=2 nosuch.pem",
        "AT*M2M*WF_EAPCERT=2 ca.pem 3 tls.pem 4 key.pem",
        "AT*M2M*WF_EAPCERT=9 x",
    ],
    # WF_EAPCONF/WF_EAPCERT real 802.1X round trip against a live RADIUS
    # server (FreeRADIUS in Docker) + Enterprise-mode AP (NETGEAR R7000,
    # SSID "netgear", 2.4GHz, WPA/WPA2-Enterprise pointed at the RADIUS
    # server). PEAP/MSCHAPv2, no CA cert staged (WF_EAPCERT skipped) --
    # tests whether the board completes 802.1X auth at all before bothering
    # with server-cert validation.
    "wf_eap_live": [
        "AT*M2M*WF_MODE=?",
        "AT*M2M*WF_MODE=1",
        "AT*M2M*WF_EAPCONF=1 peap testuser testpass123",
        "AT*M2M*WF_CONN=netgear",
        "AT*M2M*WF_IPSTATUS=?",
    ],
    # WF_EAPCERT CA-cert round trip. Fixed 2026-09-13: esp_eap_client_set_ca_cert()
    # (and set_certificate_and_key()) need a length that INCLUDES the
    # terminating NUL byte load_cert_file() writes -- mbedtls_x509_crt_parse()
    # only auto-detects PEM when buf[buflen-1]=='\0', otherwise it silently
    # misparses as DER and fails (mbedtls_x509_crt_parse returned -0x2180 /
    # MBEDTLS_ERR_X509_INVALID_FORMAT). The resulting "PEAP SSL init failed"
    # surfaced as a confusing client self-NAK loop ("Peer NAK'd our request
    # for PEAP (25) with a request for PEAP (25)") that FreeRADIUS eventually
    # aborted at 50 round trips -- looked exactly like an AP/RADIUS/ESP-IDF
    # interop bug until verbose wpa debug logging (CONFIG_ESP_WIFI_DEBUG_PRINT
    # + CONFIG_LOG_MAXIMUM_LEVEL_VERBOSE) pinned the real cause. Needs a local
    # HTTP server on the test PC serving RADIUS's ca.pem (see
    # C:\\Dev\\PRJ\\80.Docker\\RADIUS\\ca.pem) at the URL below -- adjust the
    # IP/port to match your environment.
    "wf_eapcert_live": [
        "AT*M2M*WF_MODE=1",
        "AT*M2M*WF_EAPCONF=1 peap testuser testpass123",
        "AT*M2M*WF_CONN=netgear",
        "AT*M2M*NET_HTTPDOWNLOAD=http://192.168.10.2:8090/ca.pem ca.pem",
        "AT*M2M*WF_DISCONN",
        "AT*M2M*WF_EAPCERT=2 ca.pem",
        "AT*M2M*WF_CONN=netgear",
        "AT*M2M*WF_IPSTATUS=?",
    ],
    # NET_CONN/NET_SERVER type=ssl (doc Ch.4.2/8.4) command-surface check.
    # Full external round-trip (real peer, cert file on SPIFFS) needs LAN
    # connectivity this environment didn't have this session (AP client
    # isolation blocked device-to-device traffic on the only reachable AP) --
    # same category of gap as WF_EAPCONF/EAPCERT's missing RADIUS server.
    # This only exercises what's reachable without a peer: arg validation,
    # missing-cert-file rejection, and a real (if unreachable) connect
    # attempt to prove the esp_tls code path runs on hardware without
    # crashing and fails cleanly.
    "net_ssl": [
        "AT*M2M*WF_MODE=?",
        "AT*M2M*NET_SERVER=1 ssl 8443",
        "AT*M2M*NET_SERVER=1 ssl 8443 nosuchfile.pem",
        "AT*M2M*NET_CONN=0 ssl 203.0.113.1 443 0",
        "AT*M2M*NET_STATUS=?",
        "AT*M2M*NET_DISCONN",
    ],
    "wf_apmode_full": [
        "AT*M2M*WF_MODE=?",
        "AT*M2M*WF_APMODE=2 m2m_apmode_test 6 12345678",
        "AT*M2M*WF_APMODE=?",
        "AT*M2M*WF_IPSTATUS=?",
        "AT*M2M*WF_MODE=0",
        "AT*M2M*WF_APMODE=1",
        "AT*M2M*WF_IPSTATUS=?",
        "AT*M2M*WF_APMODE=0",
        "AT*M2M*WF_APMODE=?",
        "AT*M2M*WF_MODE=?",
    ],
    # SYS_LSLEEP (doc Ch.2): query default, then each real esp_wifi_set_ps()
    # mode (0/1/3), then mode 2 (light sleep) which this board rejects with
    # "reason: 0-not supported" since CONFIG_PM_ENABLE is off. Also an
    # out-of-range value for the generic AT_ERR_ARG path.
    "sys_lsleep": [
        "AT*M2M*SYS_LSLEEP=?",
        "AT*M2M*SYS_LSLEEP=1",
        "AT*M2M*SYS_LSLEEP=?",
        "AT*M2M*SYS_LSLEEP=3",
        "AT*M2M*SYS_LSLEEP=?",
        "AT*M2M*SYS_LSLEEP=2",
        "AT*M2M*SYS_LSLEEP=9",
        "AT*M2M*SYS_LSLEEP=0",
        "AT*M2M*SYS_LSLEEP=?",
    ],
    # SYS_ANTENNA (doc Ch.2): query default (0), set 0 (succeeds, already
    # wired), set 1 (this board has no antenna-diversity switch -- expects
    # "reason: 0-not supported"), then an out-of-range value.
    "sys_antenna": [
        "AT*M2M*SYS_ANTENNA=?",
        "AT*M2M*SYS_ANTENNA=0",
        "AT*M2M*SYS_ANTENNA=1",
        "AT*M2M*SYS_ANTENNA=?",
        "AT*M2M*SYS_ANTENNA=5",
    ],
}


def run(port: str, baud: int, lines, read_seconds: float):
    with serial.Serial(port, baud, timeout=0.2) as ser:
        for line in lines:
            cmd = (line + "\r").encode()
            print(f">> {line}")
            ser.write(cmd)
            deadline = time.time() + read_seconds
            while time.time() < deadline:
                data = ser.read(256)
                if data:
                    sys.stdout.write(data.decode(errors="replace"))
                    sys.stdout.flush()


def interactive(port: str, baud: int):
    with serial.Serial(port, baud, timeout=0.1) as ser:
        print(f"Connected to {port} @ {baud}. Type AT commands, Ctrl+C to quit.")
        while True:
            data = ser.read(256)
            if data:
                sys.stdout.write(data.decode(errors="replace"))
                sys.stdout.flush()
            line = sys.stdin.readline()
            if not line:
                break
            ser.write((line.strip() + "\r").encode())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="Serial port wired to the AT UART (NOT the console port)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--read-seconds", type=float, default=3.0, help="How long to collect output after each line")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--interactive", action="store_true")
    group.add_argument("--sequence", choices=sorted(SEQUENCES.keys()))
    args = ap.parse_args()

    if args.interactive:
        interactive(args.port, args.baud)
    else:
        run(args.port, args.baud, SEQUENCES[args.sequence], args.read_seconds)


if __name__ == "__main__":
    main()
