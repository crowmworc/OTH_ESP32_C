# HANDOFF — 재설치 후 바로 이어서 작업하기

> **포맷 후 재개는 M2M 저장소의 `HANDOFF.md`(2026-10-09 갱신)를 먼저 볼 것** — 백업 목록, 두 저장소 clone, 빌드 환경 함정(ESP_ROM_ELF_DIR, Windows 애플리케이션 제어의 ld.exe 차단), 보드 상태, M2M/OTH 현황과 다음 할 일이 한 곳에 정리돼 있다. 아래는 이전 내용.

> **이 저장소(OTH_ESP32_C)는 OTH-AT 빌드용이다.** 아래 내용은 M2M 저장소 기준으로
> 쓴 것이고, 빌드·플래시·보드 주의사항은 그대로 적용된다. OTH 관련 현황은
> `README.md` 맨 위 설명과 Progress Phase 16-21, `doc/OTH-AT_Command_Status.xlsx`를 볼 것.
> 테스트 AP는 kangaps25(보드에 프로필 저장, AUCONMODE=1), AWS 페어링 파일은 보드에 저장돼 있다.
> **최신 재개 지점(2026-10-06): README Phase 22** — 결정에 따라 OTH AWS를 OTH Platform
> 방식(SoftAP 페어링 → 인증서버 → MQTT)으로 재구현. 미검증: 앱 페어링, 실서버 인증서/MQTT.
> 비교 검토 배경은 `doc/OTH-AT_vs_ICT_260808_Review.md`.
> **2026-10-09: README Phase 23** — M2M에서 가져온 Wi-Fi 무한 재접속(3회 3초 간격 → `ASSOCIATED:2` → 20초 휴식 반복), 부팅 중 명령 보류 큐(최대 10개/16KB, 초과 `ERROR 7`), USB 1KB 분할 쓰기. AP 끔/켬 포함 실기 검증 완료.

PC를 포맷하고 GitHub에서 다시 받은 뒤 바로 작업을 재개하기 위한 문서.
기준일: **2026-10-05** (GitHub `main` = 이 문서를 추가한 커밋).
기능별 상세 변경 이력은 `README.md`의 **Progress** 섹션(Phase 0~15)이 원본이다.

---

## 0. 포맷 전에 백업할 것 (Git에 없음)

| 경로 | 내용 | 왜 필요한가 |
|---|---|---|
| `C:\Dev\PRJ\80.Docker\` | RADIUS(FreeRADIUS)·MQTT(Mosquitto) 테스트 서버 `docker-compose.yml` + 인증서(CA/서버/클라이언트) | 802.1X, MQTT TLS/mTLS/WSS 재검증 |
| `C:\Dev\PRJ\85.AWS\IoT-Core-Test\` | AWS IoT Core 테스트 리소스 메모, claim 인증서 | `AWS_PROVISION` 재검증 (인증서는 안전한 곳에만 보관) |
| `C:\Doc\3.Resources\03_설계문서\EN 18031-1\` | EN 18031-1 표준 PDF, Nemko 평가 템플릿, 참고 질의서 | EN 18031-1 작업 근거 문서 |
| `C:\Dev\PRJ\90.IMG\HTTP-WEB\` | 웹 UI 디자인 레퍼런스 이미지 | 웹 UI 수정 시 |
| `C:\Users\<user>\.claude\projects\...\memory\` | Claude 세션 메모리 | 선택 (이 문서가 대체) |

> 소스·문서(`doc/`)·SBOM은 전부 GitHub에 있다. 위 폴더들만 따로 챙기면 된다.

---

## 1. 저장소 구조와 작업 방식

- **GitHub**: `https://github.com/crowmworc/M2M_ESP32_C3.git`, 브랜치 `main`.
- 포맷 전에는 두 폴더를 썼다.
  - `C:\Dev\PRJ\01.ESP32\ESP32_C3` — 실제 작업 폴더. 별도의 로컬 git 이력(remote 없음, 브랜치 `master`).
  - `C:\Dev\SVN\01.ESP32\M2M_ESP32_C3` — 이름은 SVN이지만 **git**이며 GitHub에 연결된 저장소. PRJ 커밋을 `git format-patch` → `git am`으로 옮긴 뒤 트리 해시가 같은지 확인하고 push했다.
- **포맷 후 권장**: GitHub를 한 곳에 clone 해서 그 폴더에서 바로 작업·커밋·push. 두 폴더 운영은 더 이상 필요 없다.

```powershell
git clone https://github.com/crowmworc/M2M_ESP32_C3.git C:\Dev\PRJ\01.ESP32\ESP32_C3
```

---

## 2. 개발 환경 재구축

### 2.1 설치 목록
| 항목 | 버전 / 비고 |
|---|---|
| ESP-IDF | **v5.5.4** (현재 빌드 기준). v5.5.5 업그레이드 권장 — §6 참고 |
| ESP-IDF 툴체인 | Espressif Windows Installer가 같이 설치 (riscv32-esp-elf, cmake, ninja) |
| Python | IDF 설치기가 만드는 venv 사용. 테스트용으로 `pip install pyserial` |
| Git | — |
| Docker Desktop | RADIUS/MQTT 테스트 서버용 |
| (선택) esp-idf-sbom | SBOM 재생성용, §5.4 |

### 2.2 빌드
정상 설치라면 `ESP-IDF 5.5 PowerShell` 바로가기에서:
```powershell
cd C:\Dev\PRJ\01.ESP32\ESP32_C3
idf.py build
```

`export.ps1`이 Python 버전 불일치로 실패하면(포맷 전 PC에서 실제로 발생) 환경 변수를 직접 설정한다. 경로는 설치 버전에 맞게 고칠 것:
```powershell
$env:IDF_PATH = "C:\Espressif\frameworks\esp-idf-v5.5.4"
$env:IDF_TOOLS_PATH = "C:\Espressif"
$env:IDF_PYTHON_ENV_PATH = "C:\Espressif\python_env\idf5.5_py3.11_env"
$env:PATH = "$env:IDF_PYTHON_ENV_PATH\Scripts;C:\Espressif\tools\cmake\3.30.2\bin;C:\Espressif\tools\ninja\1.12.1;C:\Espressif\tools\riscv32-esp-elf\esp-14.2.0_20260121\riscv32-esp-elf\bin;" + $env:PATH
python "$env:IDF_PATH\tools\idf.py" build
```
Windows 코드페이지(cp949) 문제로 Python 도구가 죽으면 `$env:PYTHONUTF8 = "1"`.

### 2.3 플래시 (USB, COM7)
```powershell
python -m esptool --chip esp32c3 --port COM7 -b 460800 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 4MB --flash_freq 80m 0x0 build\bootloader\bootloader.bin 0x8000 build\partition_table\partition-table.bin 0x19000 build\ota_data_initial.bin 0x60000 build\esp32_c3.bin
```
- 플래시 4MB. 파티션: nvs 0x9000(64K) / otadata / phy / storage 0x1C000(256K, SPIFFS) / ota_0 0x60000(1792K) / ota_1 0x220000(1792K), 마지막 128K 예비.
- `esptool read_flash` 시 `--after no_reset`을 쓰면 보드가 부트로더에 머문다 → `--after hard_reset` 사용.

### 2.4 AT 명령 테스트
```powershell
python tools\at_test.py --port COM7 --interactive
```
- COM7은 USB Serial/JTAG라서 **포트를 열고 닫을 때마다 보드가 리셋**된다. 한 테스트 시퀀스 동안 연결 하나를 계속 열어 둘 것. 직접 스크립트를 쓸 때는 열기 전에 DTR/RTS를 꺼 둔다.
- 부팅 직후 `WF_MODE`는 0(NULL)이다. `WF_SCAN`/`WF_CONN` 전에 `AT*M2M*WF_MODE=1` 필요.

---

## 3. ⚠ 반드시 알아야 할 보드 상태

- **COM7 보드는 eFuse KEY5에 NVS 암호화용 HMAC 키가 구워져 있다 (되돌릴 수 없음).**
  - 앞으로 이 보드에 올리는 펌웨어는 `sdkconfig`의 `CONFIG_NVS_ENCRYPTION=y`, `CONFIG_NVS_SEC_KEY_PROTECT_USING_HMAC=y`, `CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=5`를 **유지해야 한다**. 끄면 NVS를 읽을 수 없어 초기화된다.
  - 새 보드에 현재 펌웨어를 올리면 첫 부팅 때 KEY5에 키가 자동으로 구워진다 (역시 영구적).
- 개인키 파일(`PRIVATE KEY`, `.key/.p12/.pfx/.pac`)은 SPIFFS가 아니라 암호화 NVS(`m2m_files`, 최대 8KB)에 저장된다.
- 마지막 상태(2026-10-04): Phase C 이후 펌웨어(ota_1 실행), 웹 로그인은 공장 초기값(첫 접속 시 비밀번호 변경 강제), HTTP :80 실행, storage 비어 있음, `WF_APMODE=0`이라 리셋하면 Wi-Fi 연결이 끊긴다.

---

## 4. 테스트 인프라

| 대상 | 내용 |
|---|---|
| **Wi-Fi (일반)** | `kangaps25` — 클라이언트 간 통신 허용, PC↔보드 테스트 가능 |
| **Wi-Fi (피해야 할 AP)** | `LGWiFi_F7CE` — 클라이언트 격리. PC↔보드 통신 테스트 불가 |
| **Wi-Fi (Enterprise)** | `netgear` (NETGEAR R7000) — WPA2-Enterprise, Docker RADIUS 연동. 현재 위치에서 범위 밖일 수 있음 |
| **RADIUS** | `80.Docker\RADIUS` (PEAP/MSCHAPv2, 1812/udp). 계정·shared secret은 해당 폴더 설정 파일 참고 |
| **MQTT** | `80.Docker\MQTT` — 1883 평문 / 8883 TLS / 8884 mTLS / 9001 WSS. 서버 인증서에 PC LAN IP SAN이 있어야 보드 접속이 됨 (IP가 바뀌면 재발급) |
| **AWS IoT** | Fleet Provisioning by Claim 경로 검증 완료 (`85.AWS` 메모 참고) |

- `docker ps`가 실패하면 Docker Desktop을 먼저 실행할 것 (컨테이너는 restart 정책으로 자동 기동).
- 인증서를 보드에 올리는 방법: 웹 UI `/api/certs/upload` (`ca.pem`/`client.crt`/`client.key`) 또는 `AT*M2M*NET_HTTPDOWNLOAD`.

---

## 5. 진행 현황 요약

### 5.1 AT 명령
- 총 65건: 검증완료 60 / 검증필요 2 / 구현필요 1(`SYS_DSLEEP`) / 기타 2.
- 상태표: `doc/M2M-AT_Command Set_status.xlsx`. 스펙: `doc/M2M-AT Command Set.docx` (Rev 1.11).

### 5.2 주요 기능 (모두 실기 검증)
- Wi-Fi(PSK/Enterprise/WPS/SoftAP/BLE 프로비저닝), TCP/UDP/SSL 소켓·서버, HTTP 클라이언트, HTTP/HTTPS 웹 설정 서버(화면 8개), MQTT(평문/TLS/mTLS/WSS), AWS IoT Fleet Provisioning, OTA(AT·웹).

### 5.3 EN 18031-1 진행표 (`doc/EN18031-1_To-Do.xlsx`)
| 단계 | 내용 | 상태 |
|---|---|---|
| Phase A | 웹 비밀번호 해시(PBKDF2), 로그인 실패 잠금, 세션 만료, 첫 접속 비밀번호 변경 강제, 기기별 BLE PoP | 완료 |
| B-06 | 파티션 재배치 (storage 256K, OTA 1792K×2) | 완료 |
| Phase C | TLS 1.3, 약한 키 거부, DoS 제한, 입력값 검증 | 완료 (Enterprise CA 번들 폴백만 실기 미검증) |
| B-03 | NVS 암호화 (eFuse HMAC), 개인키 NVS 이동 | 완료 |
| D-01 | SBOM(SPDX) + CVE 검토 (`doc/SBOM/`) | 완료 |
| B-01/02/04/05 | Secure Boot, Flash 암호화 등 | **보류** (검토 의견만 기록, 사용자 결정 전 구현 금지) |

### 5.4 SBOM 재생성 (ESP-IDF 변경·릴리스 때마다)
```powershell
pip install esp-idf-sbom
$env:PYTHONUTF8 = "1"
esp-idf-sbom -n --no-progress create --rem-config --rem-unused -o doc\SBOM\esp32_c3.spdx build\project_description.json
esp-idf-sbom check doc\SBOM\esp32_c3.spdx
```
NVD API 키 없이 돌리면 HTTP 429가 날 수 있다 → 1~2분 기다렸다 재시도.

---

## 6. 다음 할 일

### 결정 대기 (사용자)
1. **A-14** 비밀번호 강도 규칙: 현행 유지 / (2) ID 포함·반복·연속 숫자 거부 / (3) + 흔한 단어 차단 목록.
2. **A-15** 공장 출하 기본 비밀번호: AT로 공통 비밀번호를 넣으면 첫 접속 변경 강제가 우회됨 → `web_auth.c`의 `DEFAULT_PW` 변경 또는 기기별 랜덤 + 라벨 방식 중 선택.
3. **SYS_DSLEEP**: 스펙 본문이 비어 있음. 사용자가 직접 검토 중 — 먼저 손대지 말 것.
4. Secure Boot / Flash 암호화 적용 여부와 키 보관 방식.

### 바로 진행 가능
5. **ESP-IDF v5.5.5 업그레이드** — mbedTLS 3.6.6(CVE-2026-34874) + DHCPS(CVE-2026-45160) 수정 포함. 업그레이드 후 SBOM 재생성.
6. **Phase D 나머지 문서** — 취약점 처리 절차, 사용자 가이드의 인터페이스 목록.
7. **`doc/M2M Web Configuration Service User Guide.docx` 갱신** — 로그인/첫 접속 비밀번호 변경 흐름 반영.
8. **WebUI 스크린샷** — 첫 접속 비밀번호 변경 화면, About 탭 비밀번호 변경 폼 (사용자가 브라우저에서 직접 캡처).
9. **BLE_PROV** — 폰 앱으로 끝까지 진행 + 재부팅 후 재접속 실기 로그 문서화 (현재 "검증필요").

### 알려진 버그 (미수정)
10. ~~`NET_HTTPGET`/`HTTPGET` 204 응답 시 길이 0 USB 쓰기 오류~~ — 2026-10-07 수정 (OTH 02da44d). 4KB 넘는 단일 USB 쓰기 누락도 2026-10-09 수정 (README Phase 23).
11. Wi-Fi 비밀번호 오류 시 esp reason 15(4WAY_HANDSHAKE_TIMEOUT)가 문서 reason 2가 아니라 0으로 매핑됨.
12. Appendix C 에러코드와 실제 반환값 불일치 — 매핑만 문서화하고 코드는 호환성 때문에 유지하기로 결정 (status xlsx "부록 및 기타" D6).

### 참고 제약
- 앱 파티션 여유 약 7%(134KB). 현재 `-Og`(디버그 최적화) 빌드 — 공간이 필요하면 `-Os` 전환이 우선 후보.
- 파티션 테이블은 OTA로 바꿀 수 없음 (USB 재플래시 필요, storage 위치가 바뀌면 SPIFFS 내용 삭제).
- 일일 작업 기록은 Notion "일일 기록" 데이터베이스(Sync Space 아래)에 남겨 왔다.
