# windows-host-security-audit

A read-only PowerShell audit of a single Windows host's **trust, traffic and persistence** posture.

It answers one question: *has something modified this machine in a way that would let it
intercept traffic, survive reboots, or hide from the endpoint controls?*

## Why this exists

Most "security check" scripts either dump every certificate on the box — several hundred
inbox Microsoft roots that bury anything interesting — or check a handful of registry values
and call it a day. This does neither.

The certificate section reads the registry locations where roots are **explicitly added**
(`SystemCertificates\Root\Certificates` across machine, user, group policy and enterprise scopes)
rather than enumerating the `Cert:\` provider. Anything sitting in those keys was deliberately
trusted by something. That turns a 300-row wall of noise into a short list worth reading, and
it is how an injected TLS-inspection CA actually shows up.

## What it checks

| Area | Checks |
|---|---|
| Certificate trust | Explicitly-added root CAs across four scopes, injected intermediates, self-signed certs in Personal stores |
| Traffic | WinINET / WinHTTP proxy, `HTTP_PROXY` style env vars, PAC (`AutoConfigURL`), hosts-file redirection |
| Listeners | Every listening TCP port mapped to process, binary path and Authenticode signer |
| Browser policy | Forced proxy, `AutoSelectCertificateForUrls`, force-installed extensions (Chrome, Edge, Firefox) |
| Persistence | Run/RunOnce keys, startup folders, non-Microsoft scheduled tasks with LOLBin and encoded-command detection, services from user-writable paths, unquoted service paths, WMI event-subscription consumers |
| Processes | Running processes that are unsigned, or executing from temp/appdata/programdata |
| Posture | Defender real-time, tamper protection and **exclusions**, firewall profiles, BitLocker, UAC, LSA PPL, SMBv1, PowerShell v2 engine, local administrators |

Every finding is auto-triaged `HIGH` / `MED` / `INFO` so the top of the report is the part
worth reading first.

## Usage

```powershell
# Windows PowerShell 5.1
powershell -ExecutionPolicy Bypass -File .\Invoke-HostSecurityAudit.ps1

# PowerShell 7.x
pwsh -File .\Invoke-HostSecurityAudit.ps1

# Custom output location, no console noise
pwsh -File .\Invoke-HostSecurityAudit.ps1 -OutputPath C:\Audits -Quiet
```

Run elevated. Without administrative rights the machine-scope certificate stores, LSA
settings and WMI subscriptions return incomplete results — the report flags this at the top
rather than silently under-reporting.

## Output

A timestamped folder containing:

- `report.txt` — human-readable, findings ordered by severity
- `report.json` — same data, structured, for ingestion into a SIEM or a diff between runs

Nothing is written outside that folder. The script modifies no system state.

## Limitations

Worth reading before you trust the output:

- **This is not a vulnerability scanner.** It will not enumerate CVEs in installed software.
  If that is what you need, use a real vulnerability scanner.
- **Unrecognized root CAs are reported, not condemned.** Corporate PKI and TLS-inspecting
  proxies are legitimate and common. The known-CA list is deliberately conservative, so
  expect false positives in a managed enterprise environment — that is the correct bias for
  a tool whose job is to surface things for a human to look at.
- **Signature validation is Authenticode only.** A validly signed binary from a compromised
  or stolen certificate will pass.
- **Single-host scope.** No aggregation, no fleet view, no agent. Run it where you have a
  question about a specific machine.
- Requires Windows 10 / 11 or Server 2019+. Some checks depend on modules
  (`Defender`, `NetSecurity`, `BitLocker`, `ScheduledTasks`) that are absent on stripped
  installs; those checks fail silently rather than aborting the run.

## License

MIT — see [LICENSE](LICENSE).
