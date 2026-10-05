#!/usr/bin/env python3
"""
Package the current build/ output into a release-named .zip, per
doc/M2M_SW Release Naming Guide v2.0 (sections 3 and 5).

Run this AFTER `idf.py build` -- it reads the build's own generated
project_description.json/config/sdkconfig.json/flasher_args.json rather than
re-deriving anything (name, version, and every M2M_* code segment already
came from a single source: main/Kconfig.projbuild + the top-level
CMakeLists.txt's PROJECT_VER), so there is nothing here to keep in sync by
hand when a Kconfig choice changes.

    python tools/make_release.py                  # date = today (KST)
    python tools/make_release.py --date 261015     # override, e.g. for a
                                                    # re-release of the same
                                                    # source on a later date
    python tools/make_release.py --pre rc2         # pre-release suffix

Produces build/release/<NAME>/ containing:
    <NAME>_factory.bin   (esptool merge_bin: full flashable image, 0x0)
    <NAME>_ota.bin        (build/<project>.bin, unchanged bytes -- what
                            AT*M2M*OTA_UPDATE downloads)
    bin/*                 (the individual pieces the naming guide's package
                            layout calls for -- bootloader/partition-table/
                            ota_data_initial/app/flasher_args.json, copied
                            as-is from build/)
    SHA256SUMS.txt

Does not create bin/mfg_nvs.bin (ESP-AT specific, not used by this project)
or ReleaseNote_<NAME>.pdf (write that by hand per the naming guide's
required-contents list, section 6.4).
"""
import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

KST = datetime.timezone(datetime.timedelta(hours=9))  # fixed offset -- no DST, avoids needing tzdata on Windows

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_DIR = PROJECT_ROOT / "build"


def load_json(path: Path):
    if not path.exists():
        sys.exit(f"error: {path} not found -- run `idf.py build` first")
    return json.loads(path.read_text(encoding="utf-8"))


def m2m_field(cfg: dict, key: str) -> str:
    val = cfg.get(key)
    if val is None:
        sys.exit(f"error: sdkconfig.json has no {key} -- did main/Kconfig.projbuild change?")
    return val


def build_release_name(cfg: dict, proj: dict, date: str, pre: str) -> str:
    hw = "-".join(
        m2m_field(cfg, k) for k in ("M2M_CHIP_CODE", "M2M_BOARD_CODE", "M2M_FLASH_CODE", "M2M_CLK_CODE")
    )
    fw = "-".join(m2m_field(cfg, k) for k in ("M2M_APP_CODE", "M2M_CMD_CODE", "M2M_IF_CODE"))
    version = proj["project_version"]
    pre_suffix = f"-{pre}" if pre else ""
    customer = m2m_field(cfg, "M2M_CUSTOMER_CODE") + m2m_field(cfg, "M2M_REL_CODE")
    config_seg = (
        ("1" if cfg.get("M2M_PWRON_NOTIFY") else "0")
        + m2m_field(cfg, "M2M_FS_CODE")
        + m2m_field(cfg, "M2M_SEC_CODE")
    )
    return f"M2M_{hw}_{fw}_V{version}{pre_suffix}_{customer}_{config_seg}_{date}"


def sha256sums(paths, out_path: Path):
    lines = []
    for p in paths:
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{digest}  {p.name}")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--date", help="YYMMDD, default: today in KST (Naming Guide 4.7)")
    ap.add_argument("--pre", help='pre-release suffix without the dash, e.g. "rc2", "beta1", "dev"')
    args = ap.parse_args()

    proj = load_json(BUILD_DIR / "project_description.json")
    cfg = load_json(BUILD_DIR / "config" / "sdkconfig.json")
    flasher_args = load_json(BUILD_DIR / "flasher_args.json")

    date = args.date or datetime.datetime.now(KST).strftime("%y%m%d")
    name = build_release_name(cfg, proj, date, args.pre)

    out_dir = BUILD_DIR / "release" / name
    bin_dir = out_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    app_bin = BUILD_DIR / proj["app_bin"]
    ota_bin = out_dir / f"{name}_ota.bin"
    shutil.copyfile(app_bin, ota_bin)

    # Copy the individual pieces the naming guide's package layout (section
    # 5) calls for, straight from what idf.py build already produced --
    # flasher_args.json's own "flash_files" map is the authoritative list of
    # what to merge and at which offset, so merge_bin's arguments are built
    # from it instead of hardcoding 0x0/0x8000/etc here.
    merge_args = []
    for offset, rel_path in flasher_args["flash_files"].items():
        src = BUILD_DIR / rel_path
        dst = bin_dir / Path(rel_path).name
        shutil.copyfile(src, dst)
        merge_args += [offset, str(src)]
    shutil.copyfile(BUILD_DIR / "flasher_args.json", bin_dir / "flasher_args.json")

    factory_bin = out_dir / f"{name}_factory.bin"
    settings = flasher_args["flash_settings"]
    subprocess.run(
        [
            sys.executable, "-m", "esptool",
            "--chip", "esp32c3",
            "merge_bin",
            "--flash_mode", settings["flash_mode"],
            "--flash_freq", settings["flash_freq"],
            "--flash_size", settings["flash_size"],
            "-o", str(factory_bin),
        ] + merge_args,
        check=True,
    )

    sha256sums(sorted(out_dir.glob("*.bin")), out_dir / "SHA256SUMS.txt")

    print(f"Release name: {name}")
    print(f"Written to:   {out_dir}")
    print("Still needed by hand: ReleaseNote_<NAME>.pdf (Naming Guide 6.4's required contents list).")
    print("Not created (ESP-AT specific, unused by this project): bin/mfg_nvs.bin.")


if __name__ == "__main__":
    main()
