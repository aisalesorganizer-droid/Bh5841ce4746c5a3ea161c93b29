STAGE 4 STATIC TRIAGE BUNDLE

Sample: Bh5841ce4746c5a3ea161c93b29.exe
SHA-256: a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a

This bundle does NOT contain the executable sample. It contains analysis reports and read-only scripts/artifacts. The sample was not launched. Stage 4 is additional static analysis only; no runtime behavior, malware-family attribution, server endpoint, or driver load has been confirmed.

Contents:
- Stage 2 full static report
- Stage 3 load-config / import-reference addendum
- Stage 4 static verification addendum
- Stage 4 dynamic-analysis runbook for a disposable Windows VM
- Read-only static triage script (pass the original EXE path as its first argument)
- JSON and CSV results for PE sections and byte-pattern scan
- Targeted LLVM disassembly excerpt
- Previously extracted embedded config, import table, and entry-point trace
- SHA256SUMS.txt for bundle members (excluding SHA256SUMS.txt and the ZIP itself)

The byte-pattern counts are raw byte matches, not proof of executed instructions. Do not run the sample on a normal workstation.
