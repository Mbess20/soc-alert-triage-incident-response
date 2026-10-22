# SOC Alert Triage & Incident Response | Splunk Enterprise

**Hands-on cybersecurity portfolio project | Tier 1 SOC investigation | PowerShell process analysis**

> **Training disclosure:** All eight events are synthetic. This case simulates an analyst investigation; no malware was executed and no real endpoint was compromised. The destination IP and domain are reserved documentation examples.

## Overview

I used Splunk Enterprise to investigate a simulated alert involving Microsoft Word (`WINWORD.EXE`) spawning PowerShell with an encoded command. I reconstructed an event timeline, compared suspicious activity with benign process executions, reviewed script-block and network indicators, and documented a high-priority escalation recommendation. This is a **triage assessment**, not confirmation of an infection.

## Environment and data

| Component | Details |
|---|---|
| Analysis platform | Splunk Enterprise 10.6.1 on macOS |
| Data source | Synthetic CSV: `soc_lab3_powershell_alerts.csv` |
| Splunk ingestion host | `SOC-LAB-02` (upload label) |
| Simulated endpoint | `WIN-LAB-02` (CSV `Host` field) |
| Simulated user | `jordan` |
| Alert ID | `ALERT-1001` |
| Event period | October 22, 2026, 10:00–10:06 (time zone not specified in source data) |
| Total events | 8 (6 associated with `jordan`; 2 with `sam`) |

The dataset models process creation, PowerShell script-block activity, network activity, file creation, and a detection event. `EventCode` values **4688, 4104, 3, and 11** represent example Windows/Sysmon-style event identifiers; `ALERT-1001` is a synthetic detection ID. These rows are **not** a native Windows event-log export.

## Triage question and decision

**Question:** Does the sequence warrant further investigation or escalation?

**Decision:** **High-priority escalation recommended** for Tier 2 review, subject to the organization's severity criteria. Multiple related indicators support concern, but the data does not prove successful download, payload execution, persistence, lateral movement, exfiltration, or compromise.

## Reconstructed timeline

| Time | Account | Evidence | Interpretation |
|---|---|---|---|
| 10:00:00 | jordan | `WINWORD.EXE` spawned `powershell.exe -NoProfile -EncodedCommand <REDACTED_SYNTHETIC>` | Unusual Office-to-PowerShell process relationship |
| 10:00:12 | jordan | PowerShell script block referenced `Invoke-WebRequest` and `C:\Temp\update.bin` | Command references a file retrieval operation |
| 10:00:20 | jordan | Connection attempt to `203.0.113.80:443` | Attempt recorded; outcome unknown |
| 10:01:00 | jordan | `C:\Temp\update.bin` file creation event | Synthetic artifact; execution not shown |
| 10:02:00 | jordan | `ALERT-1001` detection | Detection generated after preceding events |
| 10:04:00 | jordan | `notepad.exe notes.txt` from Explorer | Benign comparison event |
| 10:05:00 | sam | `powershell.exe Get-Date` from Explorer | Benign comparison event |
| 10:06:00 | sam | `cmd.exe /c whoami` from Explorer | Benign comparison event |

All timestamps are from the synthetic CSV and are displayed without an asserted time zone.

## Investigation walkthrough — seven embedded Splunk screenshots

These are the seven unique screenshots captured during the exercise, presented in investigation order. Each image is embedded so it displays directly on GitHub. The underlying events are synthetic; the screenshots show the actual Splunk analysis of that dataset.

### 1. Initial review of the eight synthetic events in Splunk

![Initial review of the eight synthetic events in Splunk](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/01_Raw_Event_Review.png)

### 2. Event-type counts across the dataset

![Event-type counts across the dataset](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/02_Event_Type_Summary.png)

### 3. Chronological event timeline for both accounts

![Chronological event timeline for both accounts](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/03_Full_Event_Timeline.png)

### 4. Account-specific review of the six jordan events

![Account-specific review of the six jordan events](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/04_Account_Investigation.png)

### 5. Detection event shown in the event viewer

![Detection event shown in the event viewer](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/06_Detection_Event_Review.png)

### 6. Process-creation comparison for suspicious and benign activity

![Process-creation comparison for suspicious and benign activity](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/07_Process_Comparison.png)

### 7. Final six-event jordan timeline

![Final six-event jordan timeline](https://raw.githubusercontent.com/Mbess20/soc-alert-triage-incident-response/main/08_Final_Account_Timeline.png)

## Example Splunk searches

**Summarize event types:**

```spl
source="soc_lab3_powershell_alerts.csv" host="SOC-LAB-02"
| stats count by Event_Type
| sort - count
```

**Reconstruct account timeline:**

```spl
source="soc_lab3_powershell_alerts.csv" host="SOC-LAB-02" Account_Name="jordan"
| table _time Event_Type EventCode Process_Name Parent_Process Command_Line Severity
| sort _time
```

**Compare process creation events:**

```spl
source="soc_lab3_powershell_alerts.csv" host="SOC-LAB-02" Event_Type="ProcessCreate"
| table _time Account_Name Process_Name Parent_Process Command_Line Severity
| sort _time
```

All six investigation searches are provided as reusable SPL files: [Event type summary](01_event_type_summary.spl), [Full event timeline](02_full_event_timeline.spl), [Account investigation](03_jordan_investigation.spl), [Process comparison](04_process_comparison.spl), [Office-to-PowerShell activity](05_suspicious_office_powershell.spl), and [Alert details](06_alert_details.spl).

## Tier 1 SOC assessment

- **Suspicious indicators:** Word-to-PowerShell process chain; encoded command; script referencing file retrieval; related network connection attempt; file creation; alert generated by the training rule.
- **Benign comparison:** Explorer-launched `Get-Date` and `whoami` commands, and a Notepad launch, lack the same suspicious chain in this small dataset.
- **Disposition:** Escalation recommended, not confirmed compromise.
- **Recommended Tier 2 follow-up:** Validate process ancestry and command line; retrieve EDR telemetry; assess file hash and execution history; determine whether the network attempt succeeded; review additional logs and user context; decide containment based on verified evidence and policy.

## Investigation report

[Read the SOC Case 003 investigation report (Word)](SOC_Case_003_Investigation_Report.docx)

The report uses an incident-ticket format with evidence, timeline, analyst assessment, limitations, and recommended next actions. The saved Splunk report is a separate artifact within the local Splunk instance.

## Limitations and lessons learned

The eight-event synthetic dataset is deliberately small. It lacks raw EDR process trees, actual PowerShell script contents beyond the provided example, network session outcomes, file hashes, user confirmation, and persistence evidence. The encoded command is redacted, so it cannot be decoded or assessed. No remediation or containment action was performed. The exercise reinforced that a high-priority alert is a reason to investigate—not proof of compromise.

## Skills demonstrated

Splunk Enterprise · SPL · Event correlation · PowerShell telemetry review · Process ancestry · Alert triage · Severity assessment · SOC escalation documentation · Evidence-based reporting

---

**Portfolio status:** Completed simulated investigation and documentation. **All data is synthetic and used for education only.**
