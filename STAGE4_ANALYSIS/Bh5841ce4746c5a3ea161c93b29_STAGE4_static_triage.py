#!/usr/bin/env python3
"""Read-only static triage for the supplied PE sample. Never loads or executes it."""
from __future__ import annotations
import argparse, collections, csv, hashlib, json, math, re, struct
from pathlib import Path

PATTERNS = {
    "syscall_bytes_0f05": bytes.fromhex("0f 05"),
    "sysenter_bytes_0f34": bytes.fromhex("0f 34"),
    "int2e_bytes_cd2e": bytes.fromhex("cd 2e"),
    "cpuid_bytes_0fa2": bytes.fromhex("0f a2"),
    "rdtsc_bytes_0f31": bytes.fromhex("0f 31"),
    "ud2_bytes_0f0b": bytes.fromhex("0f 0b"),
    "int3_byte_cc": bytes.fromhex("cc"),
    "hlt_byte_f4": bytes.fromhex("f4"),
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def all_offsets(data: bytes, pattern: bytes):
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos < 0:
            return
        yield pos
        pos += 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sample", nargs="?", default=str(Path(__file__).with_name("Bh5841ce4746c5a3ea161c93b29.exe")))
    ap.add_argument("--out", default=str(Path(__file__).with_name("stage4_static_results")))
    args = ap.parse_args()
    path = Path(args.sample)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()

    if len(data) < 0x100 or data[:2] != b"MZ":
        raise SystemExit("Input does not look like a PE file (missing MZ header).")
    peoff = struct.unpack_from("<I", data, 0x3c)[0]
    if data[peoff:peoff+4] != b"PE\0\0":
        raise SystemExit("PE signature not found at e_lfanew.")
    coff = peoff + 4
    machine, nsects, timestamp, symptr, nsymbols, optsz, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20b:
        raise SystemExit(f"Expected PE32+ (0x20b); found {magic:#x}.")
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    imagebase = struct.unpack_from("<Q", data, opt + 24)[0]
    size_image = struct.unpack_from("<I", data, opt + 56)[0]
    dllchars = struct.unpack_from("<H", data, opt + 70)[0]
    n_dirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs = {}
    for i in range(min(n_dirs, 16)):
        rva, size = struct.unpack_from("<II", data, opt + 112 + i * 8)
        dirs[i] = {"rva_or_file_offset": rva, "size": size}
    sec_table = opt + optsz
    sections = []
    for i in range(nsects):
        s = sec_table + i * 40
        name = data[s:s+8].rstrip(b"\0").decode("latin1", errors="replace")
        vsz, va, rawsz, rawptr = struct.unpack_from("<IIII", data, s + 8)
        flags = struct.unpack_from("<I", data, s + 36)[0]
        raw = data[rawptr:rawptr+rawsz] if rawsz and rawptr < len(data) else b""
        sections.append({
            "name": name, "rva": va, "virtual_size": vsz,
            "raw_offset": rawptr, "raw_size": rawsz, "characteristics": flags,
            "raw_entropy": round(entropy(raw), 6),
            "raw_bytes_present": bool(rawsz and len(raw) == rawsz),
            "raw_end": rawptr + rawsz,
            "virtual_end_rva": va + vsz,
        })

    def rva_to_offset(rva: int):
        for s in sections:
            if s["rva"] <= rva < s["rva"] + max(s["virtual_size"], s["raw_size"]):
                delta = rva - s["rva"]
                if delta < s["raw_size"]:
                    return s["raw_offset"] + delta
                return None
        return None

    def direct_call_target(rva: int):
        off = rva_to_offset(rva)
        if off is None or off + 5 > len(data) or data[off] != 0xE8:
            return None
        rel = struct.unpack_from("<i", data, off + 1)[0]
        return rva + 5 + rel

    # Follow only the direct CALLs whose first byte is E8; do not infer function semantics.
    call_chain = []
    current = entry_rva
    visited = set()
    for _ in range(8):
        if current in visited:
            call_chain.append({"rva": current, "cycle": True})
            break
        visited.add(current)
        off = rva_to_offset(current)
        if off is None:
            call_chain.append({"rva": current, "va": imagebase + current, "file_offset": None, "note": "no raw backing"})
            break
        tgt = direct_call_target(current)
        row = {"rva": hex(current), "va": hex(imagebase + current), "file_offset": hex(off), "first_bytes": data[off:off+16].hex(" ")}
        if tgt is None:
            row["note"] = "first opcode is not a direct CALL rel32; chain ends"
            call_chain.append(row)
            break
        row["direct_call_target_rva"] = hex(tgt)
        row["direct_call_target_va"] = hex(imagebase + tgt)
        call_chain.append(row)
        current = tgt

    pattern_report = {}
    hit_locations = []
    for name, pat in PATTERNS.items():
        offsets = list(all_offsets(data, pat))
        by_section = collections.Counter()
        for off in offsets:
            for s in sections:
                if s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]:
                    by_section[s["name"]] += 1
                    break
        pattern_report[name] = {"count_entire_file": len(offsets), "count_by_section": dict(by_section), "first_20_file_offsets": [hex(x) for x in offsets[:20]]}
        if name in ("syscall_bytes_0f05", "sysenter_bytes_0f34", "int2e_bytes_cd2e"):
            for off in offsets:
                sec = next((s for s in sections if s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]), None)
                if sec:
                    rva = sec["rva"] + off - sec["raw_offset"]
                    hit_locations.append({"pattern": name, "file_offset": hex(off), "rva": hex(rva), "va": hex(imagebase + rva), "section": sec["name"], "context_hex": data[max(0, off-8):min(len(data),off+12)].hex(" ")})
    # Keep outputs compact: every hit for syscall/sysenter/int2e is emitted to CSV, not report body.
    with (outdir / "opcode_pattern_hits.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["pattern", "file_offset", "rva", "va", "section", "context_hex"])
        w.writeheader(); w.writerows(hit_locations)

    # A cautious plain-text-only scan. Hits are leads; absence is not proof of absence.
    ascii_strings = [(m.start(), m.group().decode("ascii", "ignore")) for m in re.finditer(rb"[ -~]{5,}", data)]
    string_checks = {
        "http_urls": re.compile(r"https?://[^\s\x00\"']{4,}", re.I),
        "ipv4_like": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "sys_filenames": re.compile(r"(?i)\b[\w.-]{1,80}\.sys\b"),
        "driver_service_apis": re.compile(r"(?i)\b(?:CreateServiceW?|StartServiceW?|NtLoadDriver|ZwLoadDriver)\b"),
        "process_injection_apis": re.compile(r"(?i)\b(?:VirtualAllocEx|VirtualProtectEx|WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory|NtCreateThreadEx)\b"),
    }
    string_hits = {}
    for name, pattern in string_checks.items():
        matches = [{"file_offset": hex(off), "text": text[:240]} for off, text in ascii_strings if pattern.search(text)]
        string_hits[name] = {"count": len(matches), "matches": matches[:100]}

    overlay_start = max((s["raw_end"] for s in sections), default=0)
    overlay_len = max(0, len(data) - overlay_start)
    # Entropy of the main raw-backed executable section in 64 KiB windows.
    windows = []
    main_exec = next((s for s in sections if s["name"] == "G8WQkCuI"), None)
    if main_exec:
        start, stop = main_exec["raw_offset"], main_exec["raw_offset"] + main_exec["raw_size"]
        for off in range(start, stop, 65536):
            chunk = data[off:min(off+65536, stop)]
            windows.append({"file_offset": hex(off), "size": len(chunk), "entropy": round(entropy(chunk), 6)})

    # Output section CSV, machine-readable JSON.
    with (outdir / "sections.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(sections[0].keys()))
        w.writeheader(); w.writerows(sections)
    result = {
        "analysis_mode": "read-only static; sample was not executed",
        "file": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "pe": {"pe_header_offset": hex(peoff), "machine": hex(machine), "sections": nsects, "timestamp_unix": timestamp, "timestamp_utc": __import__("datetime").datetime.fromtimestamp(timestamp, __import__("datetime").timezone.utc).isoformat(), "characteristics": hex(characteristics), "optional_header_magic": hex(magic), "image_base": hex(imagebase), "entry_rva": hex(entry_rva), "entry_va": hex(imagebase+entry_rva), "size_of_image": hex(size_image), "dll_characteristics": hex(dllchars), "dll_characteristics_notes": {"dynamic_base": bool(dllchars & 0x40), "high_entropy_va": bool(dllchars & 0x20), "nx_compat": bool(dllchars & 0x100)}, "data_directories": dirs},
        "sections": sections,
        "entry_direct_call_chain": call_chain,
        "opcode_byte_patterns": pattern_report,
        "plaintext_string_scan": string_hits,
        "overlay": {"start_offset": hex(overlay_start), "length": overlay_len},
        "main_section_64k_entropy_windows": windows,
        "interpretation_limitations": ["Byte-pattern matches are not proof of executed instructions.", "High-entropy bytes can generate incidental opcode sequences.", "No dynamic execution or runtime memory capture was performed.", "String/API-name absence does not prove behavior is absent; protected or dynamically generated code may hide it."],
    }
    (outdir / "stage4_static_results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"file": path.name, "sha256": result["sha256"], "size": len(data), "entry_chain_hops": len(call_chain), "opcode_counts": {k:v["count_entire_file"] for k,v in pattern_report.items()}, "string_scan_counts": {k:v["count"] for k,v in string_hits.items()}, "overlay_start": hex(overlay_start), "overlay_length": overlay_len, "outputs": str(outdir)}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
