# Stage 4 addendum — independent static verification and opcode-pattern triage

**Sample:** `Bh5841ce4746c5a3ea161c93b29.exe`  
**SHA-256:** `a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a`  
**File size:** 10,356,520 bytes  
**Execution status:** Static-only. The executable was not launched.

## Executive result

This pass independently re-parsed the PE headers and section table, recomputed the SHA-256, checked the direct-call bytes at the entry point with LLVM's x86-64 disassembler, and ran a whole-file byte-pattern scan. It did not recover the protected payload or establish the sample's runtime behavior.

The key correction is that the earlier `syscall` clue must be treated conservatively. The file contains **298 occurrences of the byte sequence `0F 05`** in the single high-entropy section `G8WQkCuI`. A linear disassembly from the PE entry point encounters one occurrence at RVA `0x8B142A`, but the section is not reliably disassemblable as ordinary linear code. Therefore, the presence of this opcode at that address is a **candidate instruction only**; its execution and its system-call number/effect are unproven.

## Independently confirmed identity and PE structure

- PE signature at file offset `0x78`; PE32+ (`0x20B`), AMD64 (`0x8664`).
- Preferred image base: `0x140000000`.
- Entry RVA/VA: `0xB82D5E` / `0x140B82D5E`; file offset `0x35375E`.
- COFF timestamp: `2026-10-10T07:53:13Z` (header value; not a trusted build date).
- 10 sections; six have zero raw bytes while declaring nonzero virtual sizes.
- `G8WQkCuI` raw range: offset `0x1A00`, size `0x973200`, entropy `7.857998` bits/byte.
- Across the 152 64-KiB-sized windows sampled from that section (last window shorter), entropy spans `5.712729` to `7.997837`; mean is `7.618501`. This is consistent with a mixture of dense/high-entropy material and lower-entropy regions, not evidence of a specific packer by itself.
- Security/certificate directory and base-relocation directory are zero. No CLR runtime directory is declared.
- Overlay begins at `0x9DFC00` and is 2,856 bytes, matching prior analysis.

## Entry-point direct-call chain

Direct `CALL rel32` bytes independently decode as:

1. RVA `0xB82D5E` -> RVA `0xB7551E`
2. RVA `0xB7551E` -> RVA `0xEC9A78`
3. RVA `0xEC9A78` -> RVA `0x8B1417`

At RVA `0x8B1417`, the bytes decode as stack manipulation, a direct call to RVA `0x10CE6BB`, then the `0F 05` byte sequence at RVA `0x8B142A`, followed by another direct call. The call target at RVA `0x10CE6BB` itself begins with `push imm32` and a jump. Nearby targets also enter byte sequences that do not form a coherent, straightforward function body under linear decoding.

This is evidence of deliberately difficult control flow or non-code material being interleaved with code. It is **not** enough to assert that a syscall executes, that the loader uses a particular kernel service, or that every direct-call target returns normally. There is no reliable static proof of the control-flow path after these opaque targets.

## Raw opcode-marker counts: do not interpret as executed instructions

A whole-file byte scan produced the following counts. These count raw byte sequences, not instructions decoded on reachable paths:

| Byte marker | Count |
|---|---:|
| `0F 05` (syscall opcode bytes) | 298 |
| `0F 34` (sysenter opcode bytes) | 138 |
| `CD 2E` (INT 2E bytes) | 115 |
| `0F A2` (CPUID opcode bytes) | 232 |
| `0F 31` (RDTSC opcode bytes) | 282 |
| `0F 0B` (UD2 opcode bytes) | 177 |
| `CC` (INT3 byte) | 29,946 |
| `F4` (HLT byte) | 32,014 |

Almost all matches occur in `G8WQkCuI`, whose near-maximum entropy means arbitrary instruction-looking sequences are expected. The counts do **not** substantiate anti-debugging, direct syscalls, CPU fingerprinting, or privileged-instruction execution. Those hypotheses need instruction-aware analysis of code proven reachable after any unpacking.

## Plaintext indicators revisited

A reproducible ASCII string scan found no plaintext matches for HTTP(S) URLs, IPv4-shaped strings, `.sys` filenames, common driver/service-load API names, or common process-injection API names. These were limited regular-expression checks: absence of a match is not proof of absence. UTF-16 strings, constructed strings, encrypted constants, runtime API resolution, downloaded code, and the zero-raw virtual sections remain outside the scope of that negative result.

Prior import-table facts still apply: `LoadLibraryA` and `GetProcAddress` are imported; sensitive imported APIs such as `MiniDumpWriteDump`, `CertAddCertificateContextToStore`, `NtQuerySystemInformation`, and `AdjustTokenPrivileges` are capability indicators only, because no direct RIP-relative IAT call sites were found in Stage 3. This stage did not resolve their runtime callers.

## What this pass changes

1. Revalidates file identity and call-chain addresses.
2. Downgrades the `syscall` point from a potentially over-weighted clue to a **candidate byte sequence in an opaque control-flow region**.
3. Quantifies the volume of misleading opcode-looking bytes throughout the high-entropy section.
4. Does not identify a packer, driver, endpoint, credential collection flow, persistence mechanism, or malware family.

## Current blocking issue

The protected code cannot be reliably interpreted from the raw file using the available static tools. This runtime environment is Linux-based and does not provide a Windows kernel/GUI sandbox, Windows debugging session, or memory capture of the unpacked process. Running the executable in the current environment is neither supported nor an acceptable substitute for controlled analysis.

The next evidence-producing step is a disposable Windows VM run with snapshots and instrumented event capture. See `Bh5841ce4746c5a3ea161c93b29_STAGE4_DYNAMIC_RUNBOOK.md`. No claim of dynamic verification is made in this report.
