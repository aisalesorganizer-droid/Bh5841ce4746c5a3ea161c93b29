# Stage 2 static reversing report — Bh5841ce4746c5a3ea161c93b29.exe

**Analysis date:** 2026-10-14  
**Scope:** Static analysis only; executable was not launched.  
**SHA-256:** `a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a`  
**Size:** 10,356,520 bytes (9.88 MiB)

## Executive findings

1. **Purpose is well-supported:** embedded configuration identifies `BeastHax` / `L3YZK1NG` and includes CrossFire-specific loader strings, license/subscription validation, “Load Cheat,” “Initializing Loader,” “Spoofing,” driver-load errors, and debugger-detection messages.
2. **Strong packer/obfuscation evidence:** six PE sections have nonzero virtual sizes but zero raw data, while one randomized-name executable section is about 9.2 MiB and has entropy near 7.86 bits/byte. The image retains a large x64 exception/unwind table describing thousands of functions whose code sections have no on-disk bytes. This is consistent with protected/packed code that is reconstructed in memory, but the specific protector has not been identified.
3. **Entry-point control flow is intentionally obscured:** the PE entry point `RVA 0xB82D5E` calls through `0xB7551E` → `0xEC9A78` → `0x8B1417`. The destination at `0x8B1417` begins with stack manipulation, calls into shared opaque control-flow targets, and has a reachable `syscall` instruction at `VA 0x1408B142A`. The syscall number and effect are not established.
4. **Network endpoints were not recovered:** no plaintext URL, IP address, `.sys` filename, or obvious server hostname was found. `WS2_32.dll` is imported by ordinal 116, which maps to `WSACleanup` in a public ordinal mapping; that is a cleanup API, not a connect/send API. Other network behavior may be dynamically resolved or hidden in packed regions.
5. **Manifest is not registered as a resource:** an XML fragment at file offset `0x975E00` says `requireAdministrator`, but the resource tree only exposes icon/group-icon types and has no `RT_MANIFEST` entry. Treat this XML as an orphaned/inert blob unless runtime evidence proves otherwise.
6. **A one-week expiry interval is embedded:** `BEASTSTAMP` = 2026-10-12 04:31:03 UTC; `BEASTEXPIRY` = 2026-10-19 04:30:31 UTC, a difference of 604,768 seconds (7 days minus 32 seconds).

## PE metadata

- Machine: `0x8664` (AMD64); optional-header magic: `0x20B` (PE32+).
- Preferred image base: `0x140000000`; entry point: RVA `0xB82D5E` / VA `0x140B82D5E`.
- COFF timestamp: 2026-10-10T07:53:13+00:00.
- Linker major/minor: 14, 0.
- Subsystem: `2` (Windows GUI).
- `DllCharacteristics`: `0x0120` (`HIGH_ENTROPY_VA` and `NX_COMPAT` bits are set; `DYNAMIC_BASE` is not set).
- No export directory, security/certificate table, base relocation directory, debug directory, or CLR runtime directory was declared.
- SHA-256 is a file identity, not a malware verdict.

## Section table

| Name | RVA | Virtual size | Raw offset | Raw size | Characteristics | Raw entropy |
|---|---:|---:|---:|---:|---:|---:|
| `q&@j^('J` | `0x1000` | `0x305EF6` | `0x0` | `0x0` | `0x60000020` | 0.0000 |
| `'aCwt,#&` | `0x307000` | `0x96B98` | `0x0` | `0x0` | `0x40000040` | 0.0000 |
| `PLwzS&d3` | `0x39E000` | `0x65E04` | `0x0` | `0x0` | `0xC0000040` | 0.0000 |
| `Q/RcDJN'` | `0x404000` | `0x16914` | `0x0` | `0x0` | `0x40000040` | 0.0000 |
| `I*2ta),o` | `0x41B000` | `0x9` | `0x0` | `0x0` | `0xC0000040` | 0.0000 |
| `Z&l3-AUu` | `0x41C000` | `0x4125CC` | `0x0` | `0x0` | `0x60000020` | 0.0000 |
| `737@(t;z` | `0x82F000` | `0x1510` | `0x400` | `0x1600` | `0xC0000040` | 0.2417 |
| `G8WQkCuI` | `0x831000` | `0x9730D0` | `0x1A00` | `0x973200` | `0x68000060` | 7.8580 |
| ``7m`f<+$z`` | `0x11A5000` | `0x1326` | `0x974C00` | `0x1400` | `0x40000040` | 3.4678 |
| `.rsrc` | `0x11A7000` | `0x6A000` | `0x976000` | `0x69C00` | `0x40000040` | 6.0104 |

The first six sections are virtual-only placeholders (`SizeOfRawData = 0`). The main section `G8WQkCuI` is raw-backed and executable (about 9.2 MiB); sampled 64 KiB windows reach approximately 7.997 bits/byte. The randomized section names do not identify a known packer by themselves.

## Entry-point trace

| Sequence | RVA | VA | Static observation |
|---|---:|---:|---|
| 1 | `0xB82D5E` | `0x140B82D5E` | `CALL 0x140B7551E` |
| 2 | `0xB7551E` | `0x140B7551E` | Begins with `CALL 0x140EC9A78` |
| 3 | `0xEC9A78` | `0x140EC9A78` | Begins with `CALL 0x1408B1417` |
| 4 | `0x8B1417` | `0x1408B1417` | Begins `mov [rsp+0x10], imm32; lea rsp,[rsp+0x10]; call 0x1410CE6BB; syscall; call 0x140B6F562; ...` |

The following bytes in these regions are not readily interpretable as straightforward linear code. A raw relative-branch scan found repeated references to shared opaque targets `0x10CE6BB` (20 call-pattern matches), `0x1167ED0` (40), and `0xF34BE4` (37); these are candidate xrefs from raw bytes, not proof that every occurrence executes. The control-flow structure is consistent with deliberate obfuscation. Static disassembly alone does not reveal the system service number or prove the syscall’s purpose.

The TLS directory exists at RVA `0xB44490` (`0x28` bytes), but its callback-table pointer is null; no TLS callback-based unpacking entry was declared.

## Exception/unwind table

The PE exception directory is at RVA `0x118D630`, size `0x16AA0`, containing 7,736 12-byte `RUNTIME_FUNCTION` entries. Mapping starts by virtual section shows 7,703 entries pointing into section `q&@j^('J`, which has virtual size `0x305EF6` but zero on-disk raw bytes. Two more entries point into another virtual-only executable section, and only 31 entries start in `G8WQkCuI`. This preserved metadata is consistent with a native program image whose primary code is not stored in its normal section locations on disk.

## Overlay and configuration format

- Overlay starts at file offset `0x9DFC00`; the overlay length is 2,856 bytes.
- `LEYZKBEASTLANGX` is followed by a Base64 block of 2,648 bytes. Base64 decoding yields 1,984 bytes; zlib decompression yields 4,876 bytes of JSON with 112 keys.
- The JSON was extracted to `Bh5841ce4746c5a3ea161c93b29_embedded_config.json`.
- Footer `BHXTRL` begins at offset `0x9E071C` and its length field is 2844 (`0xB1C`), exactly the offset from overlay start to the footer marker.
- `BEASTCHK0` is followed by a 31-byte opaque validation area before the footer. The leading 4-byte value does not match ordinary CRC-32 of the whole file or the tested overlay ranges; algorithm/purpose unknown.

## Key embedded strings

- `LOAD_CHEAT`: `Load Cheat`
- `LOAD_SUCCESS`: `!B34stH4x Loaded!`
- `CLOSE_GAME`: `!!CLOSE CROSSFIRE PLEASE!!`
- `INIT_DRIVER`: `Initializing Loader`
- `INIT_SPOOFER`: `..Spoofing..\nPlease wait.`
- `FOUND_DEBUGGER`: `Debugger Detected`
- `INIT_DRIVER_FAILED`, `LOAD_DRIVER_FAILED`, `LOAD_DRIVER_FAILED_2`
- `ERR_HWID_MISMATCH`, `ERR_BLACKLISTED`, `ERR_TOKEN_INVALID`, `ERR_HASH_MISMATCH`
- login/register/license/subscription errors, including expired, banned, invalid key, invalid server response, and invalid session.

The configuration supports the application-purpose assessment but does not expose API endpoints, request bodies, or the hidden implementation of the loader/driver routines.

## Imports

The full import list is in `Bh5841ce4746c5a3ea161c93b29_imports.csv`. Selected capabilities:

- `LoadLibraryA`, `GetProcAddress`, `GetModuleHandleA`, `ExitProcess`.
- `NtQuerySystemInformation`, `AdjustTokenPrivileges`.
- `MiniDumpWriteDump`, `CertAddCertificateContextToStore`, `BCryptGenRandom`.
- `D3D11CreateDeviceAndSwapChain`, GUI/graphics APIs, COM activation, and MSVC runtime.
- `WS2_32.dll` ordinal `#116` → `WSACleanup` per public export-ordinal list. Static imports for `connect`, `socket`, `send`, `recv`, `WinHTTP`, or WinINet were not identified.

An imported API proves declared dependency only, not that the function executes. The program also imports `GetProcAddress`/`LoadLibraryA`, and the principal code is protected, so the import table does not fully delimit runtime capabilities.

## Additional embedded-image checks

A raw scan found 93 `MZ` byte-pairs, 135 gzip-magic byte-pairs, and one `PE\x00\x00` signature; validation of `MZ` headers found only the outer PE at file offset `0x0`, with no validated nested PE image. The high-entropy section can still conceal compressed/encrypted content, so this does not rule out an encrypted driver or payload. A string scan did not recover plaintext URL/IPv4 endpoints, `.sys` filenames, common process-injection API names, service-start/load-driver names, or common Run-key persistence strings. These are negative static findings only.

## Security assessment

**Risk posture: high uncertainty with several high-concern indicators.** The sample is a game-cheat loader with explicit driver/spoofing workflows and difficult-to-audit protected code. A kernel driver could be highly privileged if loaded, but no driver image or `.sys` filename was recovered. `MiniDumpWriteDump` can write process memory dumps, and `CertAddCertificateContextToStore` can add a certificate to a certificate store; actual arguments/call sites and whether those operations execute remain unknown. There was no dynamic trace, malware-scanner verdict, or sandbox run in this assessment.

The XML text that requests administrator execution is not registered as a normal manifest resource. The file does not carry an embedded Authenticode signature. Neither fact proves maliciousness, but provenance and integrity cannot be validated from the file itself.

## What remains unresolved

1. Recover or observe the protected code populated into the zero-raw sections.
2. Identify all dynamically resolved APIs and the direct-syscall service/arguments.
3. Determine whether a driver is embedded, downloaded, generated, or loaded from disk.
4. Observe network destinations and credential/token fields under controlled instrumentation.
5. Validate the certificate-store and process-dump call sites.

Recommended next phase: Windows sandbox/VM with snapshots, no real credentials, and instrumentation for process, file, registry, service/driver, module-load, and network events. Do not run the sample on the normal host.

## External context (not sample attribution)

A public 2024 forum thread discusses a similarly named CrossFire PH “B34STH4X” loader and includes a commenter’s claim that a related loader was Themida-packed. That is unverified user-generated content and does **not** identify the packer or reputation of this exact SHA-256. A quick indexed search did not surface a matching record for this exact SHA-256; no usable VirusTotal/MalwareBazaar verdict was retrieved, so reputation remains unknown. A public WS2_32 ordinal list maps #116 to `WSACleanup`:
- https://phcorner.org/threads/2328432/
- https://github.com/phracker/HopperScripts/blob/master/ws2_32.txt
