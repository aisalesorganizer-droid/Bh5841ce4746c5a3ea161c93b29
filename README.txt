STAGE 5 STATIC DEEP AUDIT

Sample SHA-256:
a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a

No executable sample is included in this bundle. The sample was read, not launched.

Contents:
- Stage 5 technical report
- Reproducible standard-library Python static audit script
- JSON audit output and CSV section/exception metadata summaries
- Entry-point byte-candidate trace
- Decoded embedded configuration JSON
- Previous Stage 4 report and isolated Windows dynamic-analysis runbook

Key new result: six virtual-only sections reserve 8,566,651 bytes, and 7,705 of 7,736 exception records have non-file-backed begin/unwind addresses. This strongly suggests a protected/custom PE layout, but it does not prove how it is initialized at runtime.

The script reads the PE as data only. It does not execute or load the sample.
