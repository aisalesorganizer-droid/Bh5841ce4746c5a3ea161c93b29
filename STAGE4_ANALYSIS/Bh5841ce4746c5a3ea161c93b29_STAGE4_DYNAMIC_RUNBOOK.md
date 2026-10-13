# Stage 4B — controlled Windows dynamic-analysis runbook

## Objective

Determine which of the sample's inferred capabilities actually execute: runtime API resolution, network activity, file/registry changes, child processes, certificate-store access, dump creation, and service/driver behavior. This is an observation plan, not an instruction to bypass anti-cheat or anti-analysis controls.

## Hard safety requirements

- Use a disposable Windows VM that can be reverted to a clean snapshot. Do not use the normal workstation.
- Disable shared folders, clipboard integration, drag-and-drop, host drive mapping, and personal account sign-in.
- Use no real credentials, license keys, or personal data. Do not complete login or registration during the initial run.
- Start with networking disabled. If network behavior must be observed later, use an isolated host-only/internal virtual network and a capture/simulation service; do not bridge the VM to the home or company LAN.
- Keep Windows Defender, Secure Boot, driver-signature enforcement, and other protections enabled. Do not disable security controls merely to make the sample run.
- Take a snapshot before copying the sample in and another before each materially different experiment. Revert between experiments.

## Capture sequence

### Run A — startup observation, no debugger

1. Record the VM build, patch level, architecture, active security controls, and current snapshot name.
2. Record the sample's SHA-256 again inside the VM and confirm it matches `a2541060cafaae84072cb89d0ef94b07b5129bff58358adfdbded54254487d0a`.
3. Start Process Monitor before launching the sample. Capture process/thread activity, file-system changes, registry operations, image loads, and process creation. Preserve the native `.PML` capture.
4. Start Sysmon with a reviewed configuration that records process creation, network connections, image loads, process access, file creation, registry changes, DNS events, and driver-load events. Export the relevant Windows event logs as `.EVTX` after the run.
5. Record process tree, parent PID, child processes, loaded DLLs, image paths, command lines, exit status, and timestamps. Do not click registration/login or enter user data.
6. Observe the UI and normal startup errors for a short, bounded interval, then close the application if possible. Record any failed elevation, driver, service, or network operations.
7. Hash every file created or dropped during the run before analysis. Preserve a copy of all events and artifacts, then revert to snapshot.

### Run B — network visibility, isolated only

Perform only after Run A is reviewed. Keep the virtual network host-only/internal, with no external route. Capture DNS and packet metadata in Wireshark. A simulator such as FakeNet-NG can be used to observe attempted HTTP/DNS behavior in a laboratory network. Do not supply valid credentials or reusable tokens.

Record destination IP/port, DNS question names, SNI/HTTP host fields when visible, request methods and paths, certificate details, protocol errors, byte counts, and whether the process retries after failure. TLS-encrypted payloads should remain classified as unknown unless observed through an explicitly configured lab interception point; do not assume endpoint identity from a certificate display name alone.

### Run C — debugger comparison (optional)

Only after runs A/B and a fresh snapshot, perform a separate debugging experiment. Compare observable events with the no-debugger run to determine whether behavior changes. Since the sample emits a `Debugger Detected` status string, an altered run may be a response to instrumentation; absence of behavior under a debugger must not be interpreted as proof of safety.

Do not patch out checks or bypass anti-cheat/anti-analysis routines as part of this assessment. The goal is behavior attribution, not making the cheat operate.

## Evidence checklist

- [ ] VM snapshot identifiers and environment notes
- [ ] Pre/post SHA-256 for the sample and all dropped files
- [ ] Process Monitor `.PML`
- [ ] Sysmon `.EVTX` plus exported process, image-load, network, DNS, and driver events
- [ ] Process tree and loaded-module inventory
- [ ] PCAP from isolated-network experiment, if performed
- [ ] Screenshots of error states only (no credentials)
- [ ] Timeline aligning UI status messages with system/network events
- [ ] Explicit notes on failed/blocked actions versus successful effects

## Questions the trace must answer

1. Does it create or modify a service, load a kernel driver, or open a device object? Which exact path, service name, signer, and hash?
2. Does it write certificates to a user or machine certificate store? Which store and certificate thumbprint?
3. Does it call `MiniDumpWriteDump` or create process-memory-sized files? Which process is dumped and where is the output stored?
4. Which APIs are resolved dynamically by `GetProcAddress`, from which modules, and are they called?
5. Does it contact a remote endpoint? What host/IP, port, protocol, and data types are visible without real credentials?
6. Does it create persistence (scheduled task, service, startup folder, Run key, WMI subscription, or another mechanism)? Capture observed registry/file/service evidence rather than inferring from API names.
7. Does it change behavior under a debugger or when offline, and can the difference be aligned to concrete events?

## Stop conditions

Immediately stop the run and revert the VM if the sample attempts to reach the host/LAN, encrypt or alter unrelated files, disable security controls, spread to shared resources, or otherwise escape the defined experiment. Do not connect the VM to a production environment to test a suspected driver.

## Reporting standard

Classify each statement as one of: **Observed** (trace directly records it), **Strongly inferred** (multiple independent artifacts support it), **Possible** (one indicator only), or **Not determined**. A string such as `Initializing Loader` is not proof of driver loading; an imported API is not proof of a call; a network attempt is not proof of successful authentication; and a detected file is not proof that the sample created it unless the event trace establishes causality.
