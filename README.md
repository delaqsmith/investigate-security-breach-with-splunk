# 🔎 Investigate a Cyber Attack with Splunk

## 📌 Project Overview

Security Operations Center (SOC) analysts investigate security events across an organization's network to identify suspicious activity, detect potential compromises, and understand attacker behavior.

In this project, I used **Splunk Enterprise** to investigate a simulated multi-stage cyber attack against a fictional company, Frothly, using the **Boss of the SOC (BOTS) v3 dataset**.

The investigation involved analyzing Windows authentication events, identifying suspicious endpoint activity, examining PowerShell command execution, and uncovering indicators associated with PowerShell Empire command-and-control (C2) activity.

I also mapped the observed behavior to the **MITRE ATT&CK framework** and developed a Splunk alert to detect encoded PowerShell execution.

---

## 🎯 Project Objectives

- Explore an enterprise security dataset containing 80+ data source types.
- Analyze Windows authentication and process creation events.
- Identify suspicious endpoints through event correlation and activity patterns.
- Investigate PowerShell execution for potential malware indicators.
- Map observed attacker behavior to MITRE ATT&CK.
- Develop and test a Splunk detection alert.

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Splunk Enterprise | SIEM platform for searching and analyzing security events |
| SPL | Search Processing Language used for threat hunting and detection |
| BOTS v3 Dataset | Enterprise security dataset used for the investigation |
| Windows Event Logs | Authentication and process execution analysis |
| PowerShell | Investigation of suspicious command execution |
| MITRE ATT&CK | Classification of observed attacker techniques |
| Windows | Local Splunk environment |

---

## 🗂️ Investigation Workflow

The investigation followed a structured threat-hunting process, moving from initial environment reconnaissance to identifying suspicious activity and developing a detection rule.

### 1️⃣ Install Splunk and Load the Dataset

Installed **Splunk Enterprise** on a Windows machine and imported the BOTS v3 dataset from Splunk's Boss of the SOC competition.

The dataset contains security telemetry associated with a simulated attack against Frothly, providing multiple sources of evidence for investigation.

After loading the dataset, I verified that the data was searchable and explored the available sourcetypes.

**Initial data exploration:**

```spl
| tstats count where index=botsv3 by sourcetype
| sort -count
```

This search counted events across the available sourcetypes and helped identify the different sources of security telemetry available for analysis.

**Key data sources included:**

- `wineventlog` — Windows event logs.
- `stream:http` — Captured HTTP network traffic.
- `aws:cloudtrail` — AWS API activity.
- `linux_secure` — Linux authentication logs.
- `xmlwineventlog:microsoft-windows-sysmon/operational` — Windows Sysmon events.

<img width="880" height="428" alt="image" src="https://github.com/user-attachments/assets/395b9d81-1ffd-4a48-9d5a-3a8e5a07743e" />

---

### 2️⃣ Explore the Frothly Environment

Before beginning the investigation, I profiled the environment to understand its hosts, operating systems, and available security events.

**Explore all indexed events:**

```spl
index=botsv3 earliest=0
```

**Identify Windows hosts:**

```spl
index=botsv3 sourcetype="wineventlog:security"
| stats count by host
| sort -count
```
<img width="872" height="240" alt="image" src="https://github.com/user-attachments/assets/54900f2b-447d-46e4-bc88-64f4a1dbeba7" />

**Identify common Windows Event Codes:**

```spl
index=botsv3 sourcetype="wineventlog:security"
| stats count by EventCode
| sort -count
```

**Important Windows Event Codes:**

| Event Code | Description |
|---|---|
| 4688 | Process creation |
| 4624 | Successful account logon |
| 4625 | Failed account logon |

I also explored Linux authentication activity and AWS CloudTrail events to understand the broader hybrid environment.

**Explore Linux hosts:**

```spl
index=botsv3 sourcetype=linux_secure
| stats count by host
```
<img width="874" height="176" alt="image" src="https://github.com/user-attachments/assets/1df9eda0-bf23-411e-af31-4427938cc080" />

**Explore AWS API activity:**

```spl
index=botsv3 sourcetype="aws:cloudtrail"
| stats count by eventName
| sort -count
```
<img width="878" height="413" alt="image" src="https://github.com/user-attachments/assets/09968285-7d07-474f-9f74-241636069b89" />

This reconnaissance established a baseline of the available telemetry and helped identify which data sources would be useful during the investigation.

---

### 3️⃣ Hunt for the Initial Compromise

I began investigating Windows authentication activity to identify unusual login patterns and potential signs of unauthorized access.

**Search for failed logons:**

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4625
| stats count by Account_Name, host
| sort -count
```
<img width="879" height="151" alt="image" src="https://github.com/user-attachments/assets/e645323a-39b6-4f46-8e3d-cde5affbbf5c" />

**Search for successful logons:**

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4624
| stats count by Account_Name, host
| sort -count
```
<img width="877" height="380" alt="image" src="https://github.com/user-attachments/assets/d8b79437-4924-44f6-bea7-17a9e15742dd" />

The failed logon volume was relatively low compared with successful logons. This meant authentication activity alone was not sufficient to identify the suspected compromise.

I expanded the investigation to process creation events to identify endpoints generating unusual activity.

**Identify hosts with the highest process creation activity:**

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688
| stats count by host
| sort -count
```
<img width="879" height="212" alt="image" src="https://github.com/user-attachments/assets/a5d933ec-a2ee-4c91-bdcd-222a01f9761c" />

The host `BSTOLL-L` stood out because it had the highest process creation activity.

I then examined the processes launched by that endpoint.

**Investigate process execution on BSTOLL-L:**

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688 host="BSTOLL-L*"
| stats count by New_Process_Name
| sort -count
```
<img width="879" height="377" alt="image" src="https://github.com/user-attachments/assets/b59f79ac-d0c5-4d5d-933f-a23669eea712" />

The results showed unusually high activity involving `cmd.exe` and `powershell.exe`.

These findings made **BSTOLL-L the primary target for further investigation**.

---

### 4️⃣ Investigate PowerShell Empire C2 Activity

After identifying BSTOLL-L as the primary investigation target, I examined its PowerShell process command lines to determine what activity was occurring on the endpoint.

Windows Event Code 4688 records process creation activity and can include command-line information.

**Search for PowerShell execution:**

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688 host="BSTOLL-L*" New_Process_Name="*powershell*"
| table _time, Account_Name, New_Process_Name, Process_Command_Line
```
<img width="881" height="113" alt="image" src="https://github.com/user-attachments/assets/c213ddbd-a3da-4965-b42f-ddbc8854a2ff" />

The results contained encoded PowerShell commands using flags such as:

| PowerShell Flag | Description |
|---|---|
| `-enc` | Indicates an encoded PowerShell command |
| `-noP` | Runs PowerShell without loading the user's profile |
| `-sta` | Starts PowerShell using a single-threaded apartment |
| `-w 1` | Sets the PowerShell window state to hidden |

The combination of encoded PowerShell execution and suspicious process activity warranted further investigation.

#### 🔍 Investigate Post-Exploitation Activity

I searched for additional commands that could indicate system and network reconnaissance.

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688 host="BSTOLL-L*"
(Process_Command_Line="*netstat*" OR Process_Command_Line="*reg query*" OR Process_Command_Line="*wmic*")
| table _time, Process_Command_Line
```

**Observed commands:**

| Command | Investigative Significance |
|---|---|
| `netstat` | Examines network connections and listening ports |
| `reg query` | Queries Windows registry information |
| `wmic` | Accesses Windows management information |

These commands provided additional context about activity occurring on the suspicious endpoint.

By correlating the encoded PowerShell executions with the subsequent reconnaissance commands, I identified activity consistent with PowerShell Empire post-exploitation behavior.

**Investigation findings:**

- **Primary Host:** `BSTOLL-L.froth.ly`
- **Suspected Malware Framework:** PowerShell Empire
- **Key Indicator:** Encoded PowerShell execution
- **Additional Evidence:** System and network reconnaissance commands
- **Investigation Focus:** Identifying the account associated with suspicious activity and establishing the event timeline

---

### 5️⃣ Map Findings to MITRE ATT&CK

I used the **MITRE ATT&CK framework** to classify the observed behaviors and communicate the investigation findings using standardized adversary technique terminology.

Based on the evidence collected during the authentication and endpoint investigations, I mapped the observed attacker behavior to six MITRE ATT&CK techniques.

| Tactic | Technique ID | Technique | Supporting Evidence |
|---|---|---|---|
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Encoded PowerShell commands executed on BSTOLL-L. |
| Defense Evasion | T1027 | Obfuscated Files or Information | Base64-encoded PowerShell payloads executed using the `-enc` flag. |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | PowerShell commands included the `-noP` flag, which prevents profile loading. |
| Discovery | T1082 | System Information Discovery | `reg query` and `wmic` commands used to collect system information. |
| Discovery | T1049 | System Network Connections Discovery | `netstat` commands used to examine network connections and listening ports. |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | Suspected PowerShell Empire C2 communication over HTTP/HTTPS. |

**Investigation Significance**

Mapping the observed activity to MITRE ATT&CK helped me:

- **Classify attacker behavior** using standardized techniques.
- **Correlate suspicious events** across Windows authentication and process creation logs.
- **Understand the attack progression** from suspicious execution to potential post-exploitation activity.
- **Identify detection opportunities** for encoded PowerShell execution and reconnaissance commands.
- **Document findings** using terminology commonly used by SOC analysts and incident response teams.

### 📝 Evidence Validation

The PowerShell execution and discovery techniques are supported by the observed process command lines.

However, the `-noP` flag alone does not demonstrate that security tools were disabled or modified, so T1562.001 remains a candidate mapping requiring additional evidence.

Likewise, confirming T1071.001 requires network telemetry demonstrating C2 communication over HTTP/HTTPS. The suspected use of PowerShell Empire alone is insufficient to establish that technique.

**Note:** Technique mappings should be validated against the underlying event and network evidence. An encoded command or individual PowerShell flag does not independently prove a particular adversary technique.

---

### 6️⃣ Build a Splunk Detection Alert

After identifying encoded PowerShell execution as an important investigation indicator, I developed a search to identify similar activity across Windows endpoints.

**Detection query:**

```spl
index=botsv3 sourcetype="wineventlog:security" EventCode=4688 Process_Command_Line="*powershell*-enc*"
| stats count by host, Account_Name, Process_Command_Line
| where count > 0
```

**This search:**

- Filters Windows process creation events.
- Looks for PowerShell command lines containing the `-enc` flag.
- Groups results by host, account, and command line.
- Returns matching activity for further investigation.

#### ⚙️ Configure the Alert

I saved the search as a Splunk alert with the following configuration:

| Setting | Configuration |
|---|---|
| Alert Name | Encoded PowerShell Execution Detected |
| Permissions | Private |
| Alert Type | Scheduled |
| Trigger Condition | Number of results greater than 0 |
| Trigger Action | Log event |
| Additional Action | Add to triggered alerts |

#### ✅ Validate the Detection

Because the BOTS v3 dataset contains the historical activity identified during the investigation, I used it to verify that the detection search returned matching events and that the configured alert appeared in Splunk's Triggered Alerts page.
<img width="882" height="125" alt="image" src="https://github.com/user-attachments/assets/beb6be71-0298-4d22-8f10-cbf49036689e" />

This demonstrated how an investigation finding can be converted into a reusable detection search and alert.


---

## 🔍 Key Investigation Findings

The investigation identified `BSTOLL-L.froth.ly` as the primary suspicious endpoint.

| Finding | Evidence |
|---|---|
| Suspicious Endpoint | BSTOLL-L |
| Unusual Process Activity | High volume of process creation events |
| Suspicious Applications | `cmd.exe` and `powershell.exe` |
| Encoded PowerShell | Commands containing the `-enc` flag |
| Reconnaissance Activity | `netstat`, `reg query`, and `wmic` commands |
| Suspected Framework | PowerShell Empire |
| Detection Developed | Encoded PowerShell execution alert |

The combined findings supported the assessment of a suspected PowerShell Empire compromise within the simulated Frothly environment.

---

## 💡 What I Learned

Through this project, I gained practical experience with:

- Using Splunk Enterprise as a SIEM platform.
- Writing SPL queries to search, filter, aggregate, and correlate security events.
- Investigating Windows authentication and process creation logs.
- Identifying suspicious PowerShell execution patterns.
- Recognizing potential post-exploitation reconnaissance activity.
- Using multiple data sources to investigate suspicious endpoints.
- Mapping observed behaviors to MITRE ATT&CK.
- Creating and validating Splunk detection alerts.
- Documenting investigation findings in a structured format.

---

## 🚀 Potential Improvements

If I were to expand this project, I would:

- Build a comprehensive SOC dashboard for endpoint and authentication monitoring.
- Incorporate additional network telemetry to strengthen C2 identification.
- Expand detection coverage to include other suspicious PowerShell behaviors.
- Develop correlation searches combining process execution, authentication, and network activity.
- Add detection logic to reduce false positives.
- Explore automated incident response workflows using SOAR tools.

---

## 📝 Disclaimer

This project uses a historical competition dataset involving a fictional organization. The investigation is for educational and defensive cybersecurity purposes and does not represent an incident involving a real organization.
