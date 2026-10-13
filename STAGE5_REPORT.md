# Stage 5 — PE structure, exception metadata, TLS, resources, and overlay audit

**Sample:** `Bh5841ce4746c5a3ea161c93b29.exe`  
**SHA-256:** `a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a`  
**File size:** 10,356,520 bytes  
**Method:** Read-only static analysis; the sample was not executed.

## Executive result

Stage 5 exposes a more specific custom-packing/obfuscation pattern than entropy alone:

- Six of ten PE sections reserve a combined **8,566,651 bytes (about 8.17 MiB)** of virtual address space but contain **zero raw bytes in the file**.
- The PE exception directory contains **7,736** 12-byte runtime-function records. All 7,736 records have increasing begin RVAs and satisfy basic range/image-bound checks, yet **7,705 begin RVAs and 7,705 unwind-info RVAs are not file-backed**.
- The PE header reports `SizeOfUninitializedData = 0`, despite those substantial virtual-only sections.
- The TLS directory has no callback array. Its TLS index points into one of the virtual-only sections.
- An XML string requests `requireAdministrator`, but the PE resource tree contains only RT_ICON (type 3) and RT_GROUP_ICON (type 14) resources; there is no RT_MANIFEST (type 24). Automatic UAC elevation is not established by this XML fragment.

Together, these structures are **strong evidence of a custom packed, protected, or deliberately noncanonical PE layout**. They do not prove which runtime unpacking method is used, whether all table records are meaningful, or whether the packed image performs malicious actions.

## 1. File identity and PE flags

The file hash matches the previous stages. Its PE timestamp is `2026-10-10 07:53:13 UTC` (`2026-10-10 15:53:13` Philippines time). It is PE32+ AMD64, GUI subsystem, image base `0x140000000`, entry RVA `0xB82D5E`, and `SizeOfImage = 0x1211000`.

PE characteristics are `0x23`, including `IMAGE_FILE_RELOCS_STRIPPED`. The base-relocation directory is empty and `DYNAMIC_BASE` is not enabled. Consequently, this image does not advertise ordinary ASLR support even though `HIGH_ENTROPY_VA` is set. `NX_COMPAT` is set. The security directory is absent, so no embedded Authenticode signature is declared; the checksum field is zero. These facts are not malware verdicts, but reduce publisher provenance and/or hardening confidence.

## 2. Virtual-only sections and exception records

| Section | RVA | Virtual size | Raw size | Characteristics summary |
|---|---:|---:|---:|---|
| `q&@j^('J` | `0x1000` | `0x305EF6` | 0 | Code, execute/read |
| `'aCwt,#&` | `0x307000` | `0x96B98` | 0 | Read-only initialized-data flag |
| `PLwzS&d3` | `0x39E000` | `0x65E04` | 0 | Read/write initialized-data flag |
| `Q/RcDJN'` | `0x404000` | `0x16914` | 0 | Read-only initialized-data flag |
| `I*2ta),o` | `0x41B000` | `0x9` | 0 | Read/write initialized-data flag |
| `Z&l3-AUu` | `0x41C000` | `0x4125CC` | 0 | Code, execute/read |

The entry point resides instead in the highly entropic, raw-backed `G8WQkCuI` section. The PE exception directory is at RVA `0x118D630`, file offset `0x95E030`, size 92,832 bytes (exactly 7,736 records).

The audit classified the runtime-function table as follows:

| Begin-RVA location | Record count | File-backed code bytes? |
|---|---:|---|
| `q&@j^('J` | 7,703 | No |
| `Z&l3-AUu` | 2 | No |
| `G8WQkCuI` | 31 | Yes |

The unwind references follow a similar distribution: 7,703 point into the zero-raw `'aCwt,#&` section, two into the zero-raw `Z&l3-AUu` section, and 31 into `G8WQkCuI`.

This looks like metadata for a much larger logical image whose main code and unwind bytes are absent from the on-disk section backing, or metadata deliberately constructed to frustrate parsers. A likely explanation is a custom packer/protector that reserves memory for code/data materialized later. Static analysis cannot establish that later materialization occurs.

## 3. Entry-point interpretation

The entry point is RVA `0xB82D5E`, file offset `0x35375E`; its first five bytes decode as a relative `CALL`. Following direct-call displacement bytes leads to other high-entropy locations. However, disassembly of the surrounding target locations is mostly incoherent under ordinary linear x64 decoding.

Therefore the chain is documented only as **byte-level direct-CALL candidates**, not verified runtime control flow. The visible `0F 05` sequence is not sufficient to establish a syscall or name its service. The Stage 4 raw-opcode counts remain byte-pattern counts, not execution evidence.

## 4. TLS and load-configuration details

The TLS data directory is at RVA `0xB44490` (file offset `0x314E90`). The raw-data interval is an 8-byte span in the backed `.data`-like section. `AddressOfCallbacks = 0`, so no TLS callback array is declared. `AddressOfIndex` points to VA `0x1403FC620`, inside the virtual-only `PLwzS&d3` section.

The load-configuration directory is 320 bytes. It contains a security-cookie pointer into the same virtual-only writable section. The Guard CF function-table pointer and count are zero and Guard Flags are zero. These values do not demonstrate active CFG protection; nonzero auxiliary pointers alone are not proof that a mitigation is enabled.

## 5. Manifest and resources

The string at file offset `0x975DA8` is XML containing `requestedExecutionLevel level='requireAdministrator'`. It is in the raw-backed `7m`f<+$z` section, not referenced as a Windows manifest resource. The parsed resource tree has:

- RT_ICON (type 3): icon IDs 1–9.
- RT_GROUP_ICON (type 14): one group-icon resource, ID 105.
- RT_MANIFEST (type 24): absent.

Thus the XML string may be unused metadata, a decoy, or input to custom logic; Windows' standard resource-based UAC manifest behavior is not confirmed.

## 6. Overlay, expiration fields, and checksum marker

The overlay starts at file offset `0x9DFC00`, is 2,856 bytes long, and contains the custom markers and compressed configuration. The embedded Base64 block is 2,648 characters, decodes to 1,984 bytes, and zlib-decompresses to 4,876 bytes of JSON with 112 keys.

- Title: `L3YZK1NG`
- Copyright/product string: `BeastHax`
- Stored name: `Bh5841ce4746c5a3ea161c93b29`
- `BEASTSTAMP`: `2026-10-12 04:31:03 UTC`
- `BEASTEXPIRY`: `2026-10-19 04:30:31 UTC`
- `BHXTRL`: final 12 bytes are `BHXTRL 00 00 1C 0B 00 00`; the stored length `0xB1C` equals the overlay offset of the footer marker.

`BEASTCHK0` is followed by 32 opaque bytes. Tested SHA-256 candidates for the complete file, pre-overlay file, overlay, overlay-before-check marker, and ranges with the 32-byte field omitted did **not** match. The algorithm, key, and input range remain unknown. It should not be called a verified SHA-256 checksum.

## 7. Strings and external attribution

The expanded ASCII and UTF-16LE scan did not recover a plaintext URL, IPv4-like address, `.sys` filename, or common named process-injection / driver-service API string. This is only a negative result for raw strings: encrypted strings, generated names, dynamic API resolution, and downloaded content remain untested.

Exact-string/hash web searches did not surface an indexed public report for the sample hash or custom markers in the queries used. That is not evidence of a clean reputation or a malware-family attribution.

## 8. Risk assessment and what remains unknown

**Confirmed:** obfuscated/custom PE layout, virtual-only sections, opaque overlay, game-cheat/loader UI configuration, license/session/HWID-related strings, driver/spoofer status strings, lack of an Authenticode directory, no TLS callbacks, no standard RT_MANIFEST resource.

**Strongly inferred:** a custom packer, protected loader, or intentionally noncanonical image layout that complicates ordinary disassembly and may rely on runtime memory initialization.

**Not determined:** actual unpacking algorithm; whether the virtual-only sections receive code at runtime; the purpose of the syscall-shaped byte sequences; actual driver file/name/signature; network destinations and transmitted data; credential handling; certificate-store or process-dump API usage; persistence; maliciousness verdict.

## 9. Next evidence-producing step

The next meaningful step is an instrumented run in a disposable Windows VM, following the Stage 4 runbook. Capture loader events, memory-region protection changes, loaded modules, child processes, file/registry/service changes, driver loads, and isolated-network attempts. Do not disable Defender, Secure Boot, or driver-signature enforcement to force it to run. Compare any runtime memory image against the zero-raw section map above.

The original executable was not run in this environment. This report is static-only.
