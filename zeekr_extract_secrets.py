#!/usr/bin/env python3
"""
Zeekr APK Secret Extractor
===========================
Extracts the 6 secrets required for the Zeekr Home Assistant integration
(https://github.com/Fryyyyy/zeekr_homeassistant) from the Zeekr Android APK files.

Supports both storage generations:
  - App <= 1.5.5:  HMAC keys OLLVM-encrypted in libenv.so; VIN key/IV as
                   plaintext strings in DEX.
  - App >= 1.5.7:  HMAC keys in PLAINTEXT env x stage tables in libenv.so
                   (resolved via ELF relocations + ARM64 disassembly);
                   VIN key/IV moved behind iWall ECIES (fi.a / SecuritySuiteSDK)
                   and can no longer be extracted statically. Use VIN key/IV
                   from a v1.5.5 APK (still accepted by the Zeekr API) or
                   extract at runtime with Frida.

Requirements:
    pip install capstone pyelftools

Usage:
    python zeekr_extract_secrets.py <base.apk> [arm64.apk]

    - base.apk:  The main Zeekr APK (com.zeekr.global)
    - arm64.apk: The ARM64 split APK (optional, will look for .so in base if not provided)

To pull APKs from a device:
    adb shell pm path com.zeekr.global
    adb pull <path_to_base.apk> zeekr_base.apk
    adb pull <path_to_arm64.apk> zeekr_arm64.apk
"""

import argparse
import json
import os
import re
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
except ImportError:
    print("ERROR: capstone is required. Install with: pip install capstone")
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("ERROR: pyelftools is required. Install with: pip install pyelftools")
    sys.exit(1)


# ============================================================================
# Constants
# ============================================================================

# Region indices in the legacy (<= 1.5.5) OLLVM pointer tables
REGION_INDICES = {"CN": 0, "SEA": 1, "EU": 3, "EM": 3}
REGIONS_PER_ENV = 4
PROD_ENV_GROUP = 1
PROD_ENV_GROUP_EU = 0

# New (>= 1.5.7) libenv.so layout: 15 environment rows x 4 stage columns.
# Stage column 3 is always production (verified: col order is dev/test/uat/prod
# across every row, e.g. gateway-int-dev | gateway-int-test | *-uat | *-prod).
PROD_STAGE_INDEX = 3

# How to find the production row for each --region value in the new layout:
# match against the gateway hostnames of each env row.
REGION_HOST_PATTERNS = {
    "EM": "gateway-pub-em.zeekrlife.com/",
    "EU": "gateway-pub-azure.zeekr.eu/",
    "CN": "gateway-pub.zeekrlife.com/",
    "SEA": "gateway-pub-hw-em-sg.zeekrlife.com/",
}

# Known non-secret 16-char hex strings to filter out
TRIVIAL_HEX16 = {
    "0000000000000000",
    "0123456789012345",
    "0123456789abcdef",
    "9774d56d682e549c",
}


# ============================================================================
# Shared ELF helpers
# ============================================================================

class ElfHelper:
    def __init__(self, so_path: str):
        self.so_path = so_path
        with open(so_path, "rb") as f:
            self.data = f.read()
        self._parse_elf()

    def _parse_elf(self):
        with open(self.so_path, "rb") as f:
            elf = ELFFile(f)
            self.elf = elf
            self.segments = []
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_LOAD":
                    self.segments.append(
                        (
                            seg.header.p_vaddr,
                            seg.header.p_offset,
                            seg.header.p_filesz,
                            seg.header.p_memsz,
                        )
                    )
            self.relocs = {}
            for section in elf.iter_sections():
                if section.header.sh_type in ("SHT_RELA", "SHT_REL"):
                    for rel in section.iter_relocations():
                        self.relocs[rel["r_offset"]] = rel.entry.get("r_addend", 0)
            self.symbols = {}
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym:
                for sym in dynsym.iter_symbols():
                    if sym.name and sym["st_value"]:
                        self.symbols[sym.name] = sym["st_value"]

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        for seg_vaddr, seg_offset, seg_filesz, seg_memsz in self.segments:
            if seg_vaddr <= vaddr < seg_vaddr + seg_memsz:
                off = vaddr - seg_vaddr + seg_offset
                if off < seg_offset + seg_filesz:
                    return off
        return None

    def cstr(self, vaddr: int) -> str | None:
        off = self.vaddr_to_offset(vaddr)
        if off is None:
            return None
        end = self.data.find(b"\x00", off)
        if end < 0:
            return None
        return self.data[off:end].decode("utf-8", "replace")

    def deref_str(self, vaddr: int) -> str | None:
        """Pointer at vaddr -> string (via relocation addend or raw pointer)."""
        if vaddr in self.relocs:
            return self.cstr(self.relocs[vaddr])
        off = self.vaddr_to_offset(vaddr)
        if off is None:
            return None
        ptr = struct.unpack_from("<Q", self.data, off)[0]
        return self.cstr(ptr)


# ============================================================================
# New-style libenv.so resolver (app >= 1.5.7, plaintext env x stage tables)
# ============================================================================

class EnvTableResolver(ElfHelper):
    """Resolve the plaintext env x stage string tables in libenv.so (v1.5.7+).

    The JNI wrappers (getNativeApplicationId / getNativeSecret / getNativeHost)
    call small helper functions that switch on the stage index (stored by
    upDateNativeEnvironment) through a 15-entry jump table; each case loads a
    4-entry pointer table (one per brand/area) or a fixed string. All strings
    are plaintext in .rodata; pointer tables live in .data.rel.ro and are
    resolvable through the ELF relocation table.
    """

    JNI_APPID = "Java_com_zeekr_env_ServerUtils_getNativeApplicationId"
    JNI_SECRET = "Java_com_zeekr_env_ServerUtils_getNativeSecret"
    JNI_HOST = "Java_com_zeekr_env_ServerUtils_getNativeHost"

    def __init__(self, so_path: str):
        super().__init__(so_path)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.md.detail = True

    @staticmethod
    def looks_like_new_format(so_path: str) -> bool:
        data = open(so_path, "rb").read()
        if b"getNativeApplicationId" not in data:
            return False
        # new format keeps >= 3 plaintext 32-hex app ids in .rodata
        return len(re.findall(rb"^[0-9a-f]{32}$", data, re.M)) >= 3 or \
               len(re.findall(rb"\x00[0-9a-f]{32}\x00", data)) >= 3

    def _disas(self, start: int, n: int = 60):
        off = self.vaddr_to_offset(start)
        if off is None:
            return []
        return list(self.md.disasm(self.data[off : off + n * 4], start))[:n]

    def _helper_addr(self, jni_name: str) -> int | None:
        """A JNI wrapper's first `bl` targets its lookup helper."""
        wrapper = self.symbols.get(jni_name)
        if wrapper is None:
            return None
        for insn in self._disas(wrapper, 24):
            if insn.mnemonic == "bl":
                return insn.operands[0].imm
        return None

    def _parse_helper(self, start: int) -> dict:
        """Return {stage_idx: ('table', va) | ('str', va)} for a lookup helper."""
        ins = self._disas(start, 30)
        jt_va = case_base = None
        for x in ins:
            if x.mnemonic == "adr" and jt_va is None:
                jt_va = x.operands[1].imm
            elif x.mnemonic == "adr" and jt_va is not None:
                case_base = x.operands[1].imm
                break
        if jt_va is None or case_base is None:
            return {}
        # number of stages from `cmp w9, #N` guarding the jump table
        count = 15
        for x in ins:
            if x.mnemonic == "cmp" and "#0x" in x.op_str:
                try:
                    count = int(x.op_str.split("#")[1].rstrip("]"), 0) + 1
                except ValueError:
                    pass
                break
        res = {}
        jt_off = self.vaddr_to_offset(jt_va)
        for stage in range(count):
            ca = case_base + self.data[jt_off + stage] * 4
            tbl = sva = None
            bins = self._disas(ca, 12)
            for j, x in enumerate(bins):
                if x.mnemonic == "adr" and "x10" in x.op_str:
                    tbl = x.operands[1].imm
                if (
                    x.mnemonic == "adrp"
                    and j + 1 < len(bins)
                    and bins[j + 1].mnemonic == "add"
                ):
                    sva = x.operands[1].imm + bins[j + 1].operands[2].imm
            res[stage] = ("table", tbl) if tbl else ("str", sva)
        return res

    def resolve_grid(self, jni_name: str) -> dict:
        """Return {stage_idx: [4 strings]} (or {stage_idx: [string]} for fixed)."""
        helper = self._helper_addr(jni_name)
        if helper is None:
            return {}
        grid = {}
        for stage, (kind, va) in self._parse_helper(helper).items():
            if kind == "table" and va:
                grid[stage] = [self.deref_str(va + i * 8) for i in range(4)]
            elif va:
                grid[stage] = [self.cstr(va)]
        return grid

    def find_hmac_keys(self, region: str = "EM"):
        """Return (access_key, secret_key, debug_info) for the requested region."""
        appid_grid = self.resolve_grid(self.JNI_APPID)
        secret_grid = self.resolve_grid(self.JNI_SECRET)
        host_grid = self.resolve_grid(self.JNI_HOST)
        if not appid_grid or not secret_grid:
            return None, None, {"error": "no plaintext tables resolved"}

        pattern = REGION_HOST_PATTERNS.get(region, REGION_HOST_PATTERNS["EM"])

        # find env row whose prod host matches the region pattern
        matches = []
        for stage, hosts in host_grid.items():
            prod_host = hosts[PROD_STAGE_INDEX] if len(hosts) > PROD_STAGE_INDEX else hosts[0]
            if prod_host and pattern in prod_host:
                matches.append(stage)

        debug = {"host_grid": host_grid, "matches": matches, "pattern": pattern}

        if not matches:
            return None, None, debug

        # prefer the first matching row that has both tables populated
        for stage in matches:
            appids = appid_grid.get(stage, [])
            secrets = secret_grid.get(stage, [])
            if len(appids) > PROD_STAGE_INDEX and len(secrets) > PROD_STAGE_INDEX:
                access_key = appids[PROD_STAGE_INDEX]
                secret_key = secrets[PROD_STAGE_INDEX]
                if access_key and secret_key:
                    return access_key, secret_key, debug
        return None, None, debug


# ============================================================================
# Legacy native library analyzer (app <= 1.5.5, OLLVM-encrypted libenv.so)
# ============================================================================

class NativeLibAnalyzer(ElfHelper):
    """Analyze ARM64 native libraries to decrypt OLLVM-encrypted strings."""

    def decrypt_strings(self) -> dict:
        """Decrypt all OLLVM-encrypted strings using ARM64 disassembly."""
        code_end = 0
        for seg_vaddr, seg_offset, seg_filesz, seg_memsz in self.segments:
            if seg_offset == 0:
                code_end = seg_filesz
                break

        if code_end == 0:
            return {}

        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True

        best_offset = None
        best_density = 0
        chunk_size = 0x200

        for offset in range(0, min(code_end, len(self.data)) - chunk_size, 0x100):
            chunk = self.data[offset : offset + chunk_size]
            eor_count = sum(1 for i in md.disasm(chunk, offset) if i.mnemonic == "eor")
            density = eor_count / (chunk_size / 4)
            if density > best_density:
                best_density = density
                best_offset = offset

        if best_offset is None or best_density < 0.05:
            return {}

        func_start = best_offset
        for offset in range(best_offset, max(0, best_offset - 0x1000), -4):
            word = struct.unpack_from("<I", self.data, offset)[0]
            if (word & 0xFFE00000) == 0xA9800000:
                func_start = offset
                break

        func_data = self.data[func_start:code_end]
        instructions = list(md.disasm(func_data, func_start))

        xor_ops = []
        current_base = None

        for i in range(len(instructions)):
            insn = instructions[i]

            if insn.mnemonic == "adr" and len(insn.operands) == 2:
                current_base = insn.operands[1].imm
                continue

            if insn.mnemonic == "adrp" and i + 1 < len(instructions):
                next_insn = instructions[i + 1]
                if next_insn.mnemonic == "add":
                    current_base = insn.operands[1].imm + next_insn.operands[2].imm
                    continue

            if (
                insn.mnemonic == "ldrb"
                and i + 2 < len(instructions)
                and instructions[i + 1].mnemonic == "mov"
                and instructions[i + 2].mnemonic == "eor"
            ):
                mem = insn.operands[1]
                if mem.type == 3 and current_base is not None:
                    target_addr = current_base + mem.mem.disp
                    xor_val = instructions[i + 1].operands[1].imm & 0xFF
                    xor_ops.append((target_addr, xor_val))
                continue

            if (
                insn.mnemonic == "ldrb"
                and i + 1 < len(instructions)
                and instructions[i + 1].mnemonic == "eor"
            ):
                eor_insn = instructions[i + 1]
                if len(eor_insn.operands) == 3 and eor_insn.operands[2].type == 2:
                    mem = insn.operands[1]
                    if mem.type == 3 and current_base is not None:
                        target_addr = current_base + mem.mem.disp
                        xor_val = eor_insn.operands[2].imm & 0xFF
                        xor_ops.append((target_addr, xor_val))
                continue

        if not xor_ops:
            return {}

        extended = bytearray(self.data) + bytearray(0x10000)
        for addr, xor_val in xor_ops:
            off = self.vaddr_to_offset(addr)
            if off is not None and off < len(extended):
                extended[off] ^= xor_val

        addr_min = min(a for a, _ in xor_ops)
        addr_max = max(a for a, _ in xor_ops)
        off_start = self.vaddr_to_offset(addr_min)
        off_end = self.vaddr_to_offset(addr_max)

        if off_start is None or off_end is None:
            return {}

        off_end += 100

        strings = {}
        current = []
        str_start = off_start
        for j in range(off_start, min(off_end, len(extended))):
            b = extended[j]
            if b == 0:
                if len(current) >= 2:
                    s = bytes(current).decode("utf-8", errors="replace")
                    vaddr = addr_min + (str_start - off_start)
                    strings[vaddr] = s
                current = []
                str_start = j + 1
            elif 32 <= b < 127:
                current.append(b)
            else:
                current = []
                str_start = j + 1

        return strings

    @staticmethod
    def _split_into_tables(entries, max_gap=8):
        if not entries:
            return []
        tables = []
        current = [entries[0]]
        for i in range(1, len(entries)):
            gap = entries[i][0] - entries[i - 1][0]
            if gap > max_gap:
                tables.append(current)
                current = [entries[i]]
            else:
                current.append(entries[i])
        tables.append(current)
        return tables

    def find_hmac_keys(self, region: str = "EM") -> tuple:
        """Find HMAC access key and secret key (legacy OLLVM layout)."""
        strings = self.decrypt_strings()
        if not strings:
            return None, None, strings

        hex32 = re.compile(r"^[0-9a-f]{32}$")
        alnum40 = re.compile(r"^[0-9a-z]{40}$")

        region_idx = REGION_INDICES.get(region, 3)
        env_group = PROD_ENV_GROUP_EU if region == "EU" else PROD_ENV_GROUP
        target_idx = env_group * REGIONS_PER_ENV + region_idx

        appid_entries = []
        secret_entries = []

        for reloc_off in sorted(self.relocs.keys()):
            target_vaddr = self.relocs[reloc_off]
            if target_vaddr in strings:
                s = strings[target_vaddr]
                if hex32.match(s):
                    appid_entries.append((reloc_off, s))
                elif alnum40.match(s):
                    secret_entries.append((reloc_off, s))

        access_key = None
        appid_tables = self._split_into_tables(appid_entries)
        if appid_tables:
            main_table = max(appid_tables, key=len)
            if target_idx < len(main_table):
                access_key = main_table[target_idx][1]

        secret_key = None
        secret_tables = self._split_into_tables(secret_entries)
        if secret_tables:
            main_table = max(secret_tables, key=len)
            if target_idx < len(main_table):
                secret_key = main_table[target_idx][1]
            else:
                for table in secret_tables:
                    if target_idx < len(table):
                        secret_key = table[target_idx][1]
                        break

        return access_key, secret_key, strings


# ============================================================================
# DEX Secret Extraction
# ============================================================================

def extract_dex_files(apk_path: str, output_dir: str) -> list:
    """Extract all DEX files from an APK."""
    dex_files = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                z.extract(name, output_dir)
                dex_files.append(os.path.join(output_dir, name))
    return sorted(dex_files)


def extract_native_libs(apk_path: str, output_dir: str) -> list:
    """Extract ARM64 native libraries from an APK."""
    so_files = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if "arm64" in name and name.endswith(".so"):
                z.extract(name, output_dir)
                so_files.append(os.path.join(output_dir, name))
    return so_files


def find_rsa_public_key(dex_files: list) -> str | None:
    """Find the RSA public key for password encryption."""
    base64_chars = set(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    prefix = b"MIGfMA0GCSq"

    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()

            idx = 0
            while True:
                idx = data.find(prefix, idx)
                if idx == -1:
                    break

                end = idx
                while end < len(data) and data[end] in base64_chars:
                    end += 1

                key = data[idx:end].decode("ascii")
                if 200 <= len(key) <= 400:
                    return key
                idx = end
        except Exception:
            continue
    return None


def find_prod_secret(dex_files: list) -> list:
    """Find all prod secret candidates for X-SIGNATURE HMAC computation."""
    pattern = re.compile(rb"\x20([0-9a-f]{32})\x00")
    sig_candidates = []
    other_candidates = []

    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()
            has_sig = b"X-SIGNATURE" in data
            for match in pattern.finditer(data):
                val = match.group(1).decode("ascii")
                if has_sig:
                    if val not in sig_candidates:
                        sig_candidates.append(val)
                else:
                    if val not in other_candidates:
                        other_candidates.append(val)
        except Exception:
            continue

    all_candidates = sig_candidates + [v for v in other_candidates if v not in sig_candidates]
    return all_candidates


def find_vin_keys(dex_files: list) -> tuple:
    """Find the VIN encryption key and IV (plaintext, app <= 1.5.5 only)."""
    per_dex = {}
    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()

            if b"AES/CBC/PKCS5Padding" not in data:
                continue

            pattern = re.compile(rb"\x10([0-9a-f]{16})\x00")
            vals = []
            seen = set()
            for match in pattern.finditer(data):
                val = match.group(1).decode("ascii")
                if val not in TRIVIAL_HEX16 and val not in seen:
                    seen.add(val)
                    vals.append(val)
            if vals:
                per_dex[os.path.basename(dex_path)] = vals
        except Exception:
            continue

    if not per_dex:
        return None, None

    for dex_name, vals in sorted(per_dex.items()):
        if len(vals) == 2:
            return vals[0], vals[1]

    for dex_name, vals in sorted(per_dex.items()):
        if len(vals) >= 2:
            return vals[0], vals[1]
        elif len(vals) == 1:
            for other_name, other_vals in sorted(per_dex.items()):
                if other_name != dex_name:
                    for v in other_vals:
                        if v != vals[0]:
                            return vals[0], v
            return vals[0], None

    return None, None


def uses_iwall_ecies(dex_files: list) -> bool:
    """Detect the >= 1.5.7 iWall ECIES setup (fi.a + SecuritySuiteSDK)."""
    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()
            if b"Lfi/a;" in data and b"SecuritySuiteSDK" in data:
                return True
        except Exception:
            continue
    return any(
        b"SecuritySuiteSDK" in open(p, "rb").read() for p in dex_files[:20]
    )


FRIDA_HINT = """
  Runtime alternative (Frida, rooted device or emulator):

    // vin_hook.js - prints VIN AES key/IV at runtime
    Java.perform(function () {
      var A = Java.use('cj.a');
      A.h.implementation = function (content, key, iv) {
        console.log('VIN key: ' + key);
        console.log('VIN IV:  ' + iv);
        return this.h(content, key, iv);
      };
    });

    frida -U -l vin_hook.js com.zeekr.global
    (then trigger any vehicle API call in the app)
"""


# ============================================================================
# Main Extraction Pipeline
# ============================================================================

def extract_secrets(base_apk: str, arm64_apk: str = None, region: str = "EM"):
    """Extract all 6 secrets from the Zeekr APK files."""
    secrets = {
        "hmac_access_key": None,
        "hmac_secret_key": None,
        "password_public_key": None,
        "prod_secret": None,
        "prod_secret_candidates": [],
        "vin_key": None,
        "vin_iv": None,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\n{'=' * 60}")
        print(f"  Zeekr APK Secret Extractor")
        print(f"  Target region: {region}")
        print(f"{'=' * 60}\n")

        # Step 1: Extract DEX files
        print("[1/4] Extracting DEX files from base APK...")
        dex_files = extract_dex_files(base_apk, tmpdir)
        print(f"      Found {len(dex_files)} DEX files")

        # Step 2: Extract native libraries
        print("[2/4] Extracting native libraries...")
        so_files = []
        if arm64_apk:
            so_files = extract_native_libs(arm64_apk, tmpdir)
        if not so_files:
            so_files = extract_native_libs(base_apk, tmpdir)
        print(f"      Found {len(so_files)} native libraries")

        # Step 3: Extract Java-level secrets from DEX files
        print("[3/4] Searching DEX files for secrets...")

        print("      Looking for RSA password public key...")
        key = find_rsa_public_key(dex_files)
        if key:
            secrets["password_public_key"] = key
            print(f"      [OK] Password Public Key ({len(key)} chars)")
        else:
            print("      [!!] Password Public Key: NOT FOUND")

        print("      Looking for prod secret...")
        prod_candidates = find_prod_secret(dex_files)
        if prod_candidates:
            secrets["prod_secret"] = prod_candidates[0]
            secrets["prod_secret_candidates"] = prod_candidates
            if len(prod_candidates) == 1:
                print(f"      [OK] Prod Secret: {prod_candidates[0]}")
            else:
                print(f"      [OK] Prod Secret: {prod_candidates[0]} (primary)")
                for i, c in enumerate(prod_candidates[1:], 2):
                    print(f"      [OK] Prod Secret candidate {i}: {c}")
        else:
            print("      [!!] Prod Secret: NOT FOUND")

        print("      Looking for VIN encryption key and IV...")
        vin_key, vin_iv = find_vin_keys(dex_files)
        if vin_key and vin_iv:
            secrets["vin_key"] = vin_key
            secrets["vin_iv"] = vin_iv
            print(f"      [OK] VIN Key: {vin_key}")
            print(f"      [OK] VIN IV:  {vin_iv}")
        else:
            print("      [!!] VIN Key/IV: NOT FOUND in plaintext DEX")
            if uses_iwall_ecies(dex_files):
                print("      [..] This APK stores the VIN key/IV as iWall ECIES-encrypted")
                print("           blobs (fi.a / SecuritySuiteSDK) - static extraction is not")
                print("           possible. Options:")
                print("           1) Extract VIN key/IV from a v1.5.5 APK instead - those")
                print("              values are still accepted by the Zeekr API")
                print("           2) Hook the running app with Frida (see README)")

        # Step 4: Extract HMAC keys from native library
        print("[4/4] Resolving HMAC keys from libenv.so...")

        libenv_path = None
        for so_path in so_files:
            if "libenv.so" in so_path:
                libenv_path = so_path
                break

        if libenv_path is None:
            print("      [!!] libenv.so not found!")
            print("      Make sure to provide the ARM64 split APK")
        elif EnvTableResolver.looks_like_new_format(libenv_path):
            print("      Detected new plaintext table layout (app >= 1.5.7)")
            resolver = EnvTableResolver(libenv_path)
            access_key, secret_key, debug = resolver.find_hmac_keys(region)
            if access_key and secret_key:
                secrets["hmac_access_key"] = access_key
                secrets["hmac_secret_key"] = secret_key
                print(f"      [OK] HMAC Access Key: {access_key}")
                print(f"      [OK] HMAC Secret Key: {secret_key}")
            else:
                print("      [!!] Could not resolve keys for this region.")
                print(f"      Searched host pattern: {debug.get('pattern')}")
                grid = debug.get("host_grid", {})
                if grid:
                    print("      Available environment rows (stage -> prod host):")
                    for stage, hosts in sorted(grid.items()):
                        prod = hosts[PROD_STAGE_INDEX] if len(hosts) > PROD_STAGE_INDEX else hosts
                        print(f"        stage {stage}: {prod}")
        else:
            print("      Detected legacy OLLVM layout (app <= 1.5.5)")
            print("      Disassembling and decrypting libenv.so...")
            analyzer = NativeLibAnalyzer(libenv_path)
            access_key, secret_key, all_strings = analyzer.find_hmac_keys(region)

            if access_key:
                secrets["hmac_access_key"] = access_key
                print(f"      [OK] HMAC Access Key: {access_key}")
            else:
                print("      [!!] HMAC Access Key: NOT FOUND")
                hex32 = re.compile(r"^[0-9a-f]{32}$")
                candidates = [
                    (a, s) for a, s in sorted(all_strings.items()) if hex32.match(s)
                ]
                if candidates:
                    print(f"      {len(candidates)} potential candidates found:")
                    for addr, val in candidates:
                        print(f"        0x{addr:x}: {val}")

            if secret_key:
                secrets["hmac_secret_key"] = secret_key
                print(f"      [OK] HMAC Secret Key: {secret_key}")
            else:
                print("      [!!] HMAC Secret Key: NOT FOUND")
                alnum40 = re.compile(r"^[0-9a-z]{40}$")
                candidates = [
                    (a, s) for a, s in sorted(all_strings.items()) if alnum40.match(s)
                ]
                if candidates:
                    print(f"      {len(candidates)} potential candidates found:")
                    for addr, val in candidates:
                        print(f"        0x{addr:x}: {val}")

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}\n")

    all_found = True
    for key, value in secrets.items():
        if key == "prod_secret_candidates":
            continue
        status = "[OK]" if value else "[MISSING]"
        if value:
            display = value
        else:
            display = "NOT FOUND"
            if key not in ("vin_key", "vin_iv"):
                all_found = False
        print(f"  {status} {key}: {display}")
    candidates = secrets.get("prod_secret_candidates", [])
    if len(candidates) > 1:
        print(f"\n  NOTE: Multiple prod_secret candidates found. If the primary")
        print(f"  value does not work, try the others:")
        for i, c in enumerate(candidates, 1):
            print(f"    {i}. {c}")

    if all_found and secrets["vin_key"]:
        print(f"\n  All 6 secrets extracted successfully!")
    elif all_found:
        print(f"\n  4 of 6 secrets extracted. VIN key/IV require a v1.5.5 APK")
        print(f"  or runtime extraction (see notes above).")
    else:
        print(f"\n  Some secrets could not be extracted automatically.")
        print(f"  You may need to use JADX for manual inspection.")

    # Save to JSON
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(base_apk)), "zeekr_secrets.json"
    )
    with open(output_path, "w") as f:
        json.dump(secrets, f, indent=2)
    print(f"\n  Secrets saved to: {output_path}")

    return secrets


def main():
    parser = argparse.ArgumentParser(
        description="Extract secrets from Zeekr APK for Home Assistant integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s zeekr_base.apk zeekr_arm64.apk
  %(prog)s zeekr_base.apk zeekr_arm64.apk --region EU
  %(prog)s zeekr_base.apk  # Will try to find .so files in base APK

To pull APKs from a connected Android device:
  adb shell pm path com.zeekr.global
  adb pull <base_path> zeekr_base.apk
  adb pull <arm64_path> zeekr_arm64.apk
        """,
    )
    parser.add_argument("base_apk", help="Path to the main Zeekr APK (base.apk)")
    parser.add_argument(
        "arm64_apk", nargs="?", help="Path to the ARM64 split APK (optional)"
    )
    parser.add_argument(
        "--region",
        default="EM",
        choices=["CN", "SEA", "EU", "EM"],
        help="Target region (default: EM)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.base_apk):
        print(f"ERROR: File not found: {args.base_apk}")
        sys.exit(1)

    if args.arm64_apk and not os.path.exists(args.arm64_apk):
        print(f"ERROR: File not found: {args.arm64_apk}")
        sys.exit(1)

    extract_secrets(args.base_apk, args.arm64_apk, args.region)


if __name__ == "__main__":
    main()
