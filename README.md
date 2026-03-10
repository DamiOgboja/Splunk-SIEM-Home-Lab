# Splunk-SIEM-Home-Lab


# Project Overview
This lab demonstrates the end-to-end process of building a Security Information and Event Management (SIEM) environment from scratch using Splunk Enterprise Free. I configured centralized log collection from three distinct endpoints — a Windows machine, a Kali Linux attacker machine, and an Ubuntu Linux civilian endpoint — and forwarded all three into a dedicated Splunk server VM. This setup lets me observe both sides of an attack simultaneously: offensive activity originating from Kali and the corresponding defensive signals on Windows and Ubuntu. I simulated real-world attack scenarios, authored custom SPL detection queries, and built dashboards and alerts to practice SOC-style threat monitoring. I also established a normal user activity baseline to calibrate alert thresholds and reduce false positives.

# Environments & Tools
* Virtualization Platform: Oracle VirtualBox
* SIEM Server: Splunk Enterprise Free (dedicated Ubuntu VM — log aggregation only)
* Log Source 1 (Attacker): Kali Linux 2024.4 — offensive activity, nmap scans, SSH brute force origin
* Log Source 2 (Civilian & Target): Windows 10 — Security/Sysmon logs, primary attack target
* Log Source 3 (Civilian & target): Ubuntu Linux — normal user activity baseline, secondary attack target
* Log Agents: Splunk Universal Forwarder (all 3 endpoints), Sysmon with SwiftOnSecurity config (Windows)
* Network: Isolated NAT Network

# Technical Methodology

## 1. Splunk Deployment & 3-Source Log Ingestion
I installed Splunk Enterprise on a dedicated Ubuntu VM and opened port 9997 as the receiving port for forwarded logs. Crucially, this VM serves only as the SIEM — it does not double as an endpoint being monitored. I then deployed the Splunk Universal Forwarder on all three endpoint machines and configured `inputs.conf` on each with its own index so I could filter and correlate by machine in Splunk:

* **Kali (index=kali):** `/var/log/auth.log` (SSH brute force outbound attempts, sudo), `/var/log/syslog` (process activity including nmap execution)
* **Windows (index=windows):** Security Event Log (Event IDs 4624, 4625, 4720, 4732), Sysmon Operational log (process creation, network connections)
* **Ubuntu (index=ubuntu):** `/var/log/auth.log` (SSH logins, sudo), `/var/log/syslog` (general system events)

On the Windows endpoint I installed Sysmon with the SwiftOnSecurity configuration to capture detailed process creation, network connection, and image load events that native Windows Event Logs don't surface.

## 2. Normal User Activity Baseline
Before running any attack simulations, I generated normal user activity across all three machines. On Windows this included successful logins, standard application launches, and routine file browsing. On Ubuntu I ran typical SSH sessions and shell commands. On Kali I performed normal tool usage unrelated to attacks. This step was essential — having all three machines producing ambient log traffic let me establish what a quiet, normal environment looks like in Splunk before introducing attack noise, which is what made the detection thresholds meaningful rather than arbitrary.

## 3. Brute Force Simulation & Detection
I simulated brute force attacks from Kali against both the Windows and Ubuntu endpoints. From Kali's logs I could see the outbound SSH attempts leaving the machine; from Ubuntu's auth.log I could see the inbound `Failed password` entries arriving. This two-sided visibility is what makes the 3-source setup more valuable than a standard 2-machine lab.

On Windows, I used a PowerShell loop to generate repeated failed local authentication attempts, producing Event ID 4625 entries. I authored SPL queries to detect these attacks by bucketing events into 5-minute windows and alerting when a single source IP generated 5 or more failures:

```spl
index=windows EventCode=4625
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count >= 5
| sort -count
```

```spl
index=ubuntu sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\S+)"
| bucket _time span=5m
| stats count by _time, src_ip, user
| where count >= 5
```

I also wrote a higher-fidelity query to detect a successful login following multiple failures — a strong indicator of a successful compromise:

```spl
index=windows (EventCode=4625 OR EventCode=4624)
| eval event_type=if(EventCode="4624","success","failure")
| stats count(eval(event_type="failure")) as failures,
         count(eval(event_type="success")) as successes by user, src_ip
| where failures >= 3 AND successes >= 1
```

## 4. Network Scanning Simulation & Detection
I ran Nmap from Kali against both Windows and Ubuntu using a ping sweep, a SYN scan, and an aggressive OS/version detection scan. On Windows this generated a high volume of Windows Filtering Platform events (Event ID 5156). On Ubuntu the scan traffic appeared in syslog as a burst of connection attempts. I detected the scanning behavior by identifying source IPs contacting an unusually large number of distinct destination ports in a short window:

```spl
index=windows EventCode=5156
| stats dc(dest_port) as unique_ports count by src_ip
| where unique_ports > 15
| sort -unique_ports
```

With Kali as a monitored log source I could also confirm the scan was initiated from Kali's IP by cross-referencing its syslog entries showing nmap process execution at the same timestamp — something a 2-machine lab can't do.

## 5. Dashboards & Alerting
I built two dashboards in Splunk Dashboard Studio spanning all three indexes. A Security Overview panel shows failed login timelines across all hosts, top targeted users, and event volume broken down by machine. A Threat Detection panel tracks brute force trends, new account creation (Event ID 4720), port scan events, and sudo activity on both Linux machines. I configured real-time threshold alerts for brute force attempts on both platforms, port scan detection, new admin account creation, and the success-after-failure compromise indicator.

# Key Security Takeaways

**Monitoring the attacker machine is underrated.** Having Kali as its own log source means I can see the full kill chain — the nmap scan leaving Kali and the corresponding port scan detection hitting Windows at the same timestamp. In a real environment this is analogous to having EDR on every host including ones you suspect are compromised, which is what lets you confirm lateral movement rather than just detect the destination.

**Sysmon dramatically improves Windows visibility.** Native Windows Event Logs miss a lot of process and network activity that Sysmon captures natively. Deploying it with a well-tuned config is one of the highest-value steps in a Windows monitoring setup.

**Baselines matter more than thresholds.** Setting a brute force alert to 5 failures in 5 minutes sounds reasonable, but without establishing what normal looks like first across all three machines, that threshold generates constant noise. The baseline step is what made the alerts actually actionable.

**Success-after-failure is the more dangerous signal.** A flood of 4625 events is noisy and obvious. A few failures followed by a 4624 from the same IP is quieter but far more indicative of a real compromise — this correlation query would be the first thing I'd build in a production SOC environment.

# Deliverables
[Full Technical Report]()
