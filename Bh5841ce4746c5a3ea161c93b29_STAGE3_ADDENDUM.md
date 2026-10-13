# Stage 3 addendum — load configuration, mitigation metadata, and import-call references

**Sample:** `Bh5841ce4746c5a3ea161c93b29.exe`  
**SHA-256:** `a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a`  
**Scope:** Additional static checks only. The executable was not launched.

## 1. Load configuration directory

The PE load-configuration directory is declared at RVA `0x118D4F0`, size `0x140`, and has raw backing at file offset `0x95DEF0`. Its `Size` field is `0x140`.

Nonzero pointer fields observed in the structure include:

| Field | Value | Static interpretation |
|---|---:|---|
| `SecurityCookie` | VA `0x14039E040` | Points into virtual-only section `PLwzS&d3`; cookie contents are not present in the corresponding raw section bytes. |
| `GuardCFCheckFunctionPointer` | VA `0x140BAF6A0` | Nonzero metadata pointer; actual runtime contents and use are not verified. |
| `GuardCFDispatchFunctionPointer` | VA `0x14036C490` | Points into virtual-only section `'aCwt,#&`. |
| `GuardXFGCheckFunctionPointer` | VA `0x14036C498` | Points into the same virtual-only region. |
| `GuardXFGDispatchFunctionPointer` | VA `0x14036C4A0` | Points into the same virtual-only region. |
| `GuardXFGTableDispatchFunctionPointer` | VA `0x14036C4A8` | Points into the same virtual-only region. |
| `CastGuardOsDeterminedFailureMode` | VA `0x14036C4B0` | Points into the same virtual-only region. |
| `GuardMemcpyFunctionPointer` | VA `0x14036C4B8` | Points into the same virtual-only region. |

The decoded `GuardFlags` field is zero, and the Guard CF function-table pointer/count are zero. The PE `DllCharacteristics` value is `0x0120`: `NX_COMPAT` and `HIGH_ENTROPY_VA` are set, while `DYNAMIC_BASE` is not. The base-relocation directory is absent. Therefore, the pointer values in the load-config structure **do not by themselves prove that CFG/XFG protections are active**; the metadata may be incomplete, transformed by the protection scheme, or otherwise inert in the on-disk image. Runtime verification would be needed.

## 2. Static references to imported APIs

A byte-pattern scan of raw-backed PE sections searched for common x64 RIP-relative indirect `CALL` (`FF 15 disp32`) and `JMP` (`FF 25 disp32`) instructions, plus several common RIP-relative `MOV` and `LEA` forms, that resolve directly to the declared IAT region (`RVA 0x82F000` through `0x82F207`). The scan found **zero direct matches**.

This is a limited pattern check, not a full x64 control-flow analysis. It does not prove that the imports are unused: code may call through wrappers, indirect tables, dynamically resolved pointers, or code reconstructed in the virtual-only sections. It does mean no ordinary direct RIP-relative call-site evidence was recovered by this pass for APIs such as `MiniDumpWriteDump`, `CertAddCertificateContextToStore`, `NtQuerySystemInformation`, or `AdjustTokenPrivileges`.

A second ASCII/UTF-16LE string scan found that the visible occurrences of names such as `LoadLibraryA`, `GetProcAddress`, `MiniDumpWriteDump`, `CertAddCertificateContextToStore`, `NtQuerySystemInformation`, and `AdjustTokenPrivileges` are their import-name entries. The scan did not recover separate plaintext strings naming `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`, `CreateService`, `NtLoadDriver`, WinHTTP/WinINet functions, or common Run-key persistence paths. This is a negative string-scan result only; API names could be encoded or constructed at runtime.

## 3. What this pass changes

- Confirms the load-config directory is present and contains nonzero security-cookie / Guard CF / XFG pointer metadata, but mitigation activation is **not confirmed** because flags/counts are zero and target regions include virtual-only sections.
- Finds no common direct RIP-relative references from file-backed sections into the IAT region. The import table should be treated as capability evidence, not proof of execution.
- Does not recover a driver image, destination endpoint, credentials-in-flight, or the purpose of the entry-reachable `syscall`.

## 4. Remaining highest-value analysis

The decisive next step is controlled Windows dynamic analysis of the protected image, with snapshots and no personal credentials: record dynamically resolved exports, network events, file/registry operations, child processes, module loads, service/driver creation, and actual syscall arguments. Given the apparent driver workflow, do not run it on the normal workstation. This addendum contains no dynamic execution results.
