# Splunk-SIEM-Home-Lab

# Project Overview
This lab demonstrates the end-to-end process of building a Security Information and Event Management (SIEM) environment from scratch using Splunk Enterprise Free. I configured centralized log collection from three distinct endpoints — a Windows 11 machine, a Kali Linux attacker machine, and an Ubuntu Linux civilian endpoint — and forwarded all three into a dedicated Splunk server VM. This setup lets me observe both sides of an attack simultaneously: offensive activity originating from Kali and the corresponding defensive signals on Windows and Ubuntu. I established automated baseline activity scripts on all three machines to simulate organic user behavior, then simulated real-world attack scenarios, authored custom SPL detection queries, and built dashboards and alerts to practice SOC-style threat monitoring.

# Environments & Tools
* Virtualization Platform: Oracle VirtualBox
* SIEM Server: Splunk Enterprise 10.2.1 (dedicated Ubuntu VM — log aggregation only, named ubuntu-splunk)
* Log Source 1 (Attacker): Kali Linux 2024.4 (host: kali) — offensive activity, nmap scans, SSH brute force origin
* Log Source 2 (Target): Windows 11 (host: Windows) — Security/Sysmon logs, primary attack target
* Log Source 3 (Civilian): Ubuntu Linux (host: Ubuntu-civilian) — normal user activity baseline, secondary attack target
* Log Agents: Splunk Universal Forwarder (all 3 endpoints), Sysmon v15.15 with SwiftOnSecurity config (Windows), auditd (Kali)
* Network: Isolated NAT Network (named SIEM, subnet 10.0.0.0/24)

# Technical Methodology

## 1. Splunk Deployment & 3-Source Log Ingestion
I installed Splunk Enterprise on a dedicated Ubuntu VM named ubuntu-splunk and configured port 9997 as the receiving port for forwarded logs. This VM serves only as the SIEM — it is not monitored as an endpoint. I created three separate indexes in Splunk — one per endpoint machine — so I could filter and correlate activity by source in every search.

I then deployed the Splunk Universal Forwarder on all three endpoint machines and configured `inputs.conf` on each to forward the relevant log sources into their respective indexes:

* **Kali (index=kali):** `/var/log/auth.log` (outbound SSH attempts, sudo), `/var/log/syslog` (process activity), `/var/log/audit/audit.log` (auditd process execution including nmap)
* **Windows (index=windows):** Security Event Log (Event IDs 4624, 4625, 4720, 4732), System Log, Application Log, Sysmon Operational log (process creation, network connections, image loads)
* **Ubuntu civilian (index=ubuntu):** `/var/log/auth.log` (SSH logins, sudo), `/var/log/syslog` (general system events)

On the Windows endpoint I installed Sysmon v15.15 using the SwiftOnSecurity configuration to capture detailed telemetry that native Windows Event Logs don't surface. On Kali I installed and enabled auditd so that tool executions like nmap are captured at the process level in audit.log.

One troubleshooting note worth documenting: during the Ubuntu civilian forwarder setup I initially named the index `linux` in Splunk, then configured the forwarder to send to `index = ubuntu`. This mismatch caused no logs to appear on the first check. I resolved it by deleting the `linux` index and creating a new one named `ubuntu` to match. Naming it `linux` was ambiguous anyway since both Kali and Ubuntu are Linux machines — `ubuntu` is the clearer and more specific name.

## 2. Automated Baseline Activity
Rather than generating one-time activity, I wrote persistent looping scripts for each machine that run continuously in the foreground and sleep for randomized intervals between cycles to simulate organic, non-mechanical user behavior. These scripts ran across all three machines before any attack simulations to establish what normal traffic looks like in Splunk.

**win_baseline.ps1 (Windows) — cycles every 20-30 minutes randomly**
- Recursively browses the Users and Program Files directories simulating normal file system navigation
- Runs `whoami` and `net user` to simulate standard user and account enumeration activity
- Runs `ipconfig` to simulate network configuration checks
- Launches and closes Notepad and Calculator to generate process creation and termination events in Sysmon
- Sleeps a randomized interval between cycles to simulate organic user behavior

**ubu_baseline.sh (Ubuntu civilian) — cycles every 10-20 minutes randomly**
- Browses common system directories (`/home`, `/etc`) to simulate routine file navigation
- Runs `whoami`, `id`, and `uname` to simulate normal user session activity
- Checks disk usage with `df -h` and running processes with `ps aux` to simulate system monitoring
- Attempts `sudo ls /root` to generate sudo authentication events in auth.log
- Sleeps a randomized interval between cycles to simulate organic user behavior

**kali_baseline.sh (Kali) — cycles every 10-20 minutes randomly**
- Runs `ifconfig` to simulate normal network interface checks
- Pings an external address to generate outbound ICMP traffic unrelated to attacks
- Browses tool directories to simulate normal researcher/analyst tool usage
- Checks system info with `uname` and disk usage with `df -h`
- Sleeps a randomized interval between cycles to keep activity pattern organic

The randomized sleep interval is intentional across all three scripts — a fixed interval would create a mechanical pulse pattern in Splunk that would itself appear anomalous and skew detection thresholds.

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

With Kali as a monitored log source I could also confirm the scan was initiated from Kali's IP by cross-referencing its audit.log entries showing nmap process execution at the same timestamp — something a 2-machine lab can't do.

## 5. Dashboards & Alerting
I built two dashboards in Splunk Dashboard Studio spanning all three indexes. A Security Overview panel shows failed login timelines across all hosts, top targeted users, and event volume broken down by machine. A Threat Detection panel tracks brute force trends, new account creation (Event ID 4720), port scan events, and sudo activity on both Linux machines. I configured real-time threshold alerts for brute force attempts on both platforms, port scan detection, new admin account creation, and the success-after-failure compromise indicator.

# Key Security Takeaways

**Monitoring the attacker machine is underrated.** Having Kali as its own log source means I can see the full kill chain — the nmap scan leaving Kali and the corresponding port scan detection hitting Windows at the same timestamp. In a real environment this is analogous to having EDR on every host including ones you suspect are compromised, which is what lets you confirm lateral movement rather than just detect the destination.

**Sysmon dramatically improves Windows visibility.** Native Windows Event Logs miss a lot of process and network activity that Sysmon captures natively. Deploying it with a well-tuned config is one of the highest-value steps in a Windows monitoring setup.

**Baselines matter more than thresholds.** Setting a brute force alert to trigger at 5 failures in 5 minutes sounds reasonable, but without establishing what normal looks like first across all three machines, that threshold generates constant noise. Automating the baseline scripts with randomized intervals — rather than running activity once — produced a realistic ambient traffic pattern that made the attack simulations stand out clearly in Splunk.

**Success-after-failure is the more dangerous signal.** A flood of 4625 events is noisy and obvious. A few failures followed by a 4624 from the same IP is quieter but far more indicative of a real compromise — this correlation query would be the first thing I'd build in a production SOC environment.

**Index naming matters.** Naming the Ubuntu civilian index `linux` caused an immediate troubleshooting situation since both Kali and Ubuntu are Linux machines. Specific, unambiguous naming — `ubuntu`, `kali`, `windows` — makes SPL queries cleaner and prevents confusion when correlating across sources.

# Deliverables
[Full Technical Report](./SIEM_Lab_Report.docx)
