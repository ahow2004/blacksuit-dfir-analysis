# BlackSuit Ransomware Incident Analysis

## Overview

This report analyzes a complex ransomware intrusion attributed to a BlackSuit affiliate, based on evidence and behavioral analysis published by The DFIR Report (May 2024). The threat actor exhibited a high level of operational sophistication, leveraging living-off-the-land binaries (LOLBins), custom loaders, malware such as SectopRAT and QDoor, and tools including Brute Ratel and Cobalt Strike. The attack culminated in a wide-scale deployment of BlackSuit ransomware via PsExec.

---

## Attack Summary

| Stage               | Technique / Tool Used                               | MITRE ID                  |
|--------------------|------------------------------------------------------|---------------------------|
| Initial Access      | Fake Zoom installer, d3f@ckloader, IDAT loader       | T1189 (Drive-by Compromise) |
| Execution           | SectopRAT injected via MSBuild.exe                  | T1127.001 (MSBuild)       |
| Persistence         | Registry Run Key startup entry                      | T1547.001                 |
| Defense Evasion     | Attrib +s +h, HijackLoader, DLL sideloading         | T1218.010, T1564.001      |
| Credential Access   | LSASS memory dump, Rubeus usage                     | T1003.001, T1558.003      |
| Discovery           | net, nltest, systeminfo, whoami, WMIC               | T1018, T1069.002, T1082   |
| Lateral Movement    | PsExec, WMIC, RDP over QDoor                        | T1021.001, T1047, T1572   |
| Exfiltration        | WinRAR + Bublup (cloud storage)                     | T1560.001, T1567.002      |
| Impact              | Shadow copy deletion, BlackSuit ransomware          | T1486, T1490              |

---

## Notable Observations

- **Fake Zoom Installer**: The attack originated with a cloned Zoom landing page used to distribute a trojanized installer embedded with a loader (d3f@ckloader).
- **Loader Chaining**: IDAT was dropped and used to inject SectopRAT into `MSBuild.exe`, which later fetched C2 instructions from Pastebin.
- **Dormant Dwell Time**: After installation, the malware remained dormant for 8 days before initiating further action.
- **Multiple C2 Frameworks**: SectopRAT, Brute Ratel (Badger), Cobalt Strike, and QDoor were used in parallel for persistence, beaconing, and movement.
- **Credential Access**: Cobalt Strike was used to dump credentials from LSASS using `PROCESS_ALL_ACCESS`. Rubeus was also observed in memory.
- **Lateral Movement**: PsExec and WMIC were used to deliver payloads, while RDP was tunneled using the proxy malware QDoor.
- **Data Exfiltration**: WinRAR was downloaded via Edge to compress files, which were exfiltrated to Bublup cloud storage.
- **Ransomware Deployment**: Files were staged on a DC, and BlackSuit ransomware was pushed using PsExec across multiple hosts.

---

## Time to Ransom

**194 hours (~9 days)**  
From initial access to ransomware execution — notably longer dwell time than many smash-and-grab ransomware attacks. Indicates stealth and coordinated staging.

---

## Detection Opportunities

- DLL Sideloading (SectopRAT via MSBuild)
- Registry Persistence
- Hidden File Creation (`attrib +s +h`)
- WMIC-based remote execution
- PsExec activity and lateral movement
- Suspicious Edge browser downloads (e.g., WinRAR)
- Bublup/SaaS cloud traffic for exfiltration
- RDP via proxy beaconing (QDoor)
- Shadow copy deletions via `vssadmin`

---

## Lessons Learned

- Multi-stage loaders with real installers (Zoom) can delay detection.
- Long dwell time requires proactive threat hunting over traditional alerting.
- Combining multiple C2 tools increases resiliency and confuses detection.
- Cloud-based exfiltration channels like Bublup often go unmonitored.
- Initial access can be subtle (malvertising, fake download pages), highlighting the importance of content filtering and end-user education.

---

## References

- [The DFIR Report – BlackSuit Ransomware](https://thedfirreport.com/2025/03/31/fake-zoom-ends-in-blacksuit-ransomware/)
- [MITRE ATT&CK](https://attack.mitre.org)
- [YARA & Sigma Rules from DFIR](https://github.com/SigmaHQ/sigma)

---
## 🧪 Simulation Overview

This project showcases a hands-on simulation of techniques associated with a BlackSuit ransomware-style attack using Atomic Red Team. Each stage in the attack chain was safely executed on a Windows lab environment and is mapped to the corresponding MITRE ATT&CK techniques. The goal is to demonstrate detection, logging, and incident analysis workflows for common adversary behaviors.

The following categories of activity were emulated:
- Discovery (e.g., system and user enumeration)
- Credential Access (e.g., LSASS access simulation)
- Execution & Persistence (e.g., PowerShell abuse, remote tools)
- Defense Evasion (e.g., registry modification)
- Impact (e.g., safe file encryption simulation)

📸 **Screenshots of each test, Sysmon events, and observed artifacts can be found in the [`images/`](images/) folder in this repository.** These visual logs support the detection summary and validate each technique's observable footprint.

This project is ideal for SOC analysts, blue teamers, or students preparing for cybersecurity certifications like CompTIA CySA+, Security+, or real-world threat detection scenarios.

## 🧪 Simulated Attack Chain

| MITRE Tactic        | Technique ID | Technique Name                        | Description                          |
|---------------------|--------------|--------------------------------------|--------------------------------------|
| Discovery           | T1082        | System Information Discovery         | Simulates `systeminfo` for recon     |
| Execution           | T1059.001    | PowerShell                           | Simulates PowerShell command exec    |
| Credential Access   | T1003.001    | LSASS Memory Dump (Simulated)        | Simulates credential dumping         |
| Persistence         | T1219        | Remote Access Software (AnyDesk)     | Simulates RAT installation           |
| Defense Evasion     | T1112        | Registry Modification                | Simulates altering system settings   |
| Impact              | T1486        | Data Encrypted for Impact            | Simulates fake ransomware encryption |

---

## 🧩 Environment Details

- 💻 Host OS: Windows 10 VM
- 🧰 Logging Tool: Sysmon + Event Viewer
- 📦 Atomic Red Team Path: `C:\AtomicRedTeam\atomics`
- 🔐 AV/EDR: [Enabled/Disabled based on test]
- 🔎 Review Method: Manual log correlation + screenshots

---
