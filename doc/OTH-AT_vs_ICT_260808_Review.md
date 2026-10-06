# OTH-AT 구현 vs ESP32_C3_260808_ver_0001 (ICT) 비교 검토

작성 2026-10-05. 대상: `C:\Dev\PRJ\01.ESP32\ESP32_C3_260808_ver_0001` (이하 old)과
이 저장소의 OTH-AT 빌드(이하 OTH, GitHub `92e546e` 기준).

## 현재 상황 (재개 지점)

- OTH-AT Phase 0~7 완료, 모두 push. 명령별 상태는 `doc/OTH-AT_Command_Status.xlsx`.
- 남은 시험: AWS_RECV(클라우드→장치) — PC의 `aws login`이 완료되지 않아 미시험.
- 보드(COM7): OTH 펌웨어, kangaps25 자동 접속(AUCONMODE=1), AWS 페어링 파일과
  장치 인증서 저장됨(Thing `esp32-oth9ccc01c0c8e4`, 테스트 계정 ap-southeast-2).
- **결정 대기(아래 6장)**: OTH AWS를 old의 위닉스 방식으로 재구현할지, 문서 밖
  기능 중 무엇을 넣을지, 4장 권장안 적용 여부.

## 1. old 소스 개요

- WF5000 AT 모뎀 레퍼런스(`C:\Dev\BAK\VSCode\hello_world`)의 ESP32-C3 이식본.
  README상 하드웨어 미검증.
- 명령은 `AT*ICT*...`로 받고 응답·알림은 `*M2M*...`로 냄(태그 불일치).
- 인용 문서(이 PC에서 못 찾음): `xn_app_aws_WINIX.c`, 위닉스 OpenAPI, 기능코드
  문서, `AWS_MCU_WIFI_command_flow_v0.0.4.xlsx`, `위닉스_제품인증Process_v1.8.pptx`,
  `위닉스_FOTA JSON 변경안_20231106.pptx`, `WF5000_Binary_UART_Protocol_User_Guide.docx`.
- `main/esp32_c3_main.c`에 시험용 Wi-Fi SSID/비밀번호 평문 하드코딩(보안 문제).

## 2. AWS — 재구현 검토 필요 (가장 큰 차이)

| 항목 | old (위닉스) | OTH 현재 |
|---|---|---|
| 페어링 | 페어링 서버 TCP 47000, DP0200으로 rootCA URL·인증서버 URL·엔드포인트·포트·지역 수신, `AWS_SET`으로도 설정 | `aws_conf.json` + `aws_claim.pem` 파일 |
| 인증 | `GET <auth>/register/token/<MAC>` → token, clientId=`<MAC>_<token>`; `GET <auth>/register/auth/<MAC>/<token>` → deviceCert/privateKey (응답 `{"body":{...}}`) | Fleet Provisioning by Claim |
| Root CA | rootCA URL에서 다운로드 | 공개 CA 번들 |
| 토픽 | `Winix/Conn\|Event\|Control\|Lwt/<group>/<model>/<clientId>` | `<thing>/up\|down/<apiNo>` |
| 메시지 | `{"header":{"deviceId","sndDate"},"values":{"apiNo","apiGroup","deviceGroup","modelId","attributes"}}`, apiGroup은 apiNo 표로 결정 | JSON 그대로 발행 |
| 연결 직후 | AWS_IND `MQTT OK` → `SUBSCRIBE OK`(Control) → A100 자동 발행(V01/V02, versionChangeW/M) → `CONNECT OK`; LWT=A102 | `CONNECT OK 0` |
| 수신 처리 | A502→A500 자동응답, A511/A531→Wi-Fi FOTA(AES-256-CBC+SHA-256 스트리밍), A521→MCU FOTA(MOTA), A001→인증서 갱신, A101→DEREGISTERED·A102·공장초기화·재부팅. 이들은 AWS_RECV로 안 올림. 그 외는 attributes(없으면 values 평탄화)를 AWS_RECV로 | 전부 AWS_RECV |
| 추가 명령 | `AWS_SET`, `MCU_READY=<ver>`(AWS_GET 10), `SETMIB 18`=modelId, `19`=deviceGroup | 없음 |
| AWS_IND 형식 | `OK`(코드 없음), `DISCONNECTED`, `DEREGISTERED` 추가 | `OK 0` |

OTH AWS 문서의 인증서버 URL·토큰·RootCA URL 1/2·Region·MCU 버전/체크섬·A5XX 모듈
처리는 old 구현과 일치 → 실제 대상 서버가 위닉스라면 old 방식으로 재구현 권장.

## 3. 문서에 없고 old에만 있는 기능

- 페어링 서버(TCP 47000): DP0100 장치정보(AES 키), DP0200 서버정보, DP0300 AP 스캔,
  DP0400 AP 정보→접속. 설계 폴더 `M2M Pairing - Server & App.docx`.
- MOTA_START/READY/DATA/DATA_END: MCU 펌웨어를 `mcu_fw` 파티션에 받아 256바이트 블록
  (`MOTA_DATA=<no> <len> <data> <crc>`, `MOTA_COUNT`, `MOTA_END=<crc>`)으로 호스트에 중계.
  A521로도 시작, 진행은 A520(102/201/202/301/900).
- OTA_FILENAME(기본 `firmware.bin`), MQTT_DISCONNECT.
- UARTPROTO 바이너리 UART(WF5000 8장, 설계 폴더 `M2M Binary UART.docx`).
- UPnP/DDNS/LPD 실제 구현.
- TCP 19999 AT 콘솔(개발용).
- CoAP·oneM2M(빌드되나 미연결), EAP(빌드 제외) — 사실상 미사용.

## 4. 같은 명령, 다른 동작 (권장안)

| 명령 | old | OTH 현재 | 권장 |
|---|---|---|---|
| OTA_VERCHECK/REQUEST | base URL + `version.txt`(정수) + `<url><파일명>`, 성공 시 자동 재부팅, http만 | URL=이미지, MM.NN | **old 방식으로 변경**(문서 "base URL", 예시 `.../ota/`) |
| MQTT_PUB | `=<메시지>` | `=3 <메시지>` | 둘 다 허용 |
| INITSCAN | 접속 시도마다 | 부팅 자동접속 때만 | old 방식 |
| 재접속 | 연결 중이면 끊김 대기 후 재설정(드라이버 assert 회피) | 즉시 재설정 | old 방식 반영 |
| SSL_SEND | `SSL_IND:6 1 OK` | 없음 | old 방식 |
| SMODE 공장 SSID | `inc_ap` | `OTH_xxxxxx` | 제품 사양 확인 |
| APSTART | AP 전용(station 끊김) | station 유지 | 현재 유지 |
| ASSOCIATED 코드 | AUTH_FAIL/HANDSHAKE→3 | →1 | 확인 필요 |

## 5. OTH 쪽이 나은 부분 (old의 문제)

- 모듈→호스트 데이터(RECV/HTTPBODY/SUB_RECV 등)를 바이트 스터핑함(문서 위반) +
  256바이트 이벤트 큐 경유로 잘림.
- SSL 클라이언트 서버 검증 없음, SSL 서버 인증서·키를 펌웨어에 내장(전 기기 공통).
- PING이 PINGREPLY 없이 손실 개수만, NW_CONN이 연결 여부 무관.
- FWUPGRADE/DATA_SOCKET/APLEASEIP 미구현, MIB/COUNTRY/TXGAIN/TCPKEEP 등 없음.
- 설정 RAM 전용, HTTPD_IDPW 평문·admin/admin, 파라미터 최대 8개.

## 6. 결정 (2026-10-06)

OTH 빌드는 OTH Platform 전용 → 6.1을 old 방식으로 재구현(README Phase 22): 페어링 서버,
인증서버/RootCA, 토픽·메시지 형식, A5XX·A001·A101 처리, AWS_SET, MCU_READY, SETMIB 18/19,
MOTA_*. 6.2의 나머지(OTA_FILENAME, MQTT_DISCONNECT, UARTPROTO, UPnP/DDNS/LPD)와 4장
권장안은 범위 밖으로 두었다. 코드 주석에는 "OTH Platform"이라는 명칭만 쓴다.

## 6-old. 결정 대기 (2026-10-05 기록)

1. OTH AWS를 old(위닉스) 방식으로 재구현할지 — 하려면 위 인용 문서/원본 소스 위치,
   없으면 old 코드 기준으로 진행. 포함 범위: 페어링 서버, MCU_READY, AWS_SET,
   SETMIB 18/19, A5XX 자동 처리(Wi-Fi FOTA, MOTA).
2. 문서 밖 기능 중 넣을 것: MOTA_*, OTA_FILENAME, MQTT_DISCONNECT, UARTPROTO,
   UPnP/DDNS/LPD.
3. 4장 권장안 적용 여부.
