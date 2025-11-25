
---

# 🛡️ Security Operations Center (SOC) Lab

### **Enterprise-Grade Threat Detection & Incident Response with Splunk SIEM**

A hands-on SOC environment built from scratch, featuring real attack analysis, custom threat detection, Sysmon-based telemetry, and a full security dashboard monitoring an Active Directory domain.

---

## 📋 Table of Contents

* [Project Overview](#project-overview)
* [Technical Environment](#technical-environment)
* [Key Achievements](#key-achievements)
* [Attack Analysis](#attack-analysis)
* [Detection-Rule](#detection-rule)
* [Dashboard](#dashboard)
* [Installation Guide](#installation-guide)
* [Lessons Learned](#lessons-learned)
* [Future Enhancements](#future-enhancements)

---

## 🔍 Project Overview

This project simulates a real-world enterprise SOC by combining:

| Component                 | Description                                                |
| ------------------------- | ---------------------------------------------------------- |
| **SIEM**                  | Splunk Enterprise (log ingestion, correlation, dashboards) |
| **Endpoint Telemetry**    | Sysmon with SwiftOnSecurity config                         |
| **Directory Services**    | Active Directory domain with multiple Windows servers      |
| **Real Attack Traffic**   | 200,000+ brute force attempts captured live                |
| **Custom Detection Rule** | Brute Force attack alert built using SPL                   |

**Duration:** 1 week
**Skill Level:** Beginner → Intermediate
**Domain:** Cybersecurity, Detection Engineering, Incident Response

---

## 🖥️ Technical Environment

### **Infrastructure**

| Category       | Details                                         |
| -------------- | ----------------------------------------------- |
| Cloud Platform | Vultr                                           |
| Network        | VPC with segmented firewall rules               |
| Servers        | Ubuntu 22.04 (Splunk), Windows Server 2016/2019 |

### **Security Stack**

| Component                  | Purpose                      |
| -------------------------- | ---------------------------- |
| Splunk Enterprise          | SIEM / log management        |
| Splunk Universal Forwarder | Windows log forwarding       |
| Sysmon                     | High-fidelity telemetry      |
| Active Directory           | Authentication + permissions |
| Windows Event Logs         | Native security logging      |

### **Data Sources**

| Data Source           | Description                         |
| --------------------- | ----------------------------------- |
| Windows Security Logs | Logon events (4624, 4625, etc.)     |
| Sysmon Logs           | Process, DNS, registry, file events |
| Total Events          | 200,000+                            |
| Daily Ingestion       | 5,000–10,000 events/day             |

---

## 🏆 Key Achievements

### **1. Real-World Attack Discovery**

A live RDP brute force attack was identified using Splunk.

| Metric              | Value                 |
| ------------------- | --------------------- |
| Total Failed Logins | **200,000+**          |
| Attack Duration     | 24+ hours             |
| Unique Attacker IPs | 10+                   |
| Peak Attempts       | 3,300/hour            |
| Successful Breaches | **0**                 |
| Main Target         | Administrator account |

### **Top Attacking IPs**

| IP Address     | Attempts |
| -------------- | -------- |
| 93.123.109.245 | 22,587   |
| 195.178.110.98 | 15,576   |
| 2.57.121.22    | 12,714   |

### **Attack Characteristics**

| Indicator   | Description                                  |
| ----------- | -------------------------------------------- |
| Attack Type | Dictionary & credential stuffing             |
| Pattern     | International (Spanish/Portuguese usernames) |
| Behavior    | Coordinated botnet                           |
| Result      | No compromise due to strong password         |

---

### **2. Brute Force Detection Alert**

A single production-ready Splunk detection rule was created.

| Feature    | Details                                              |
| ---------- | ---------------------------------------------------- |
| Alert Name | Brute Force Login Detection                          |
| Trigger    | ≥ 10 failed logins from a single IP within 3 minutes |
| Type       | Scheduled search                                     |
| Priority   | High                                                 |
| Schedule   | Every 5 minutes                                      |

---

### **3. SOC Dashboard**

A 4-panel Splunk dashboard visualizes authentication and attack trends.

| Panel Name                      | Description                              |
| ------------------------------- | ---------------------------------------- |
| Failed Login Attempts Over Time | Line chart showing brute force spikes    |
| Top Attacking IPs               | Bar chart of most aggressive IPs         |
| Most Targeted Accounts          | Pie chart of usernames                   |
| Activity by Hour                | Column chart showing attacker peak times |

---

### **4. Sysmon Deployment**

Sysmon generated high-value telemetry across the environment:

| Sysmon Event ID | Description                  |
| --------------- | ---------------------------- |
| 1               | Process creation             |
| 3               | Network connections          |
| 10              | Process access (LSASS, etc.) |
| 11              | File creation                |
| 13              | Registry modification        |
| 22              | DNS queries                  |

| Metric         | Value  |
| -------------- | ------ |
| Process Events | 9,000+ |
| File Events    | 60+    |
| DNS Queries    | 50+    |

---

## 🚨 Attack Analysis

### **Timeline**

| Date/Time      | Event                                      |
| -------------- | ------------------------------------------ |
| Nov 19 – 03:00 | Port 3389 opened to all IP's; Attack begins|
| Nov 19 – 07:00 | Peak activity (3,300 attempts/hour)        |
| Nov 19 – 19:00 | Continued botnet traffic                   |
| Nov 20         | Attack discovered in Splunk                |
| Nov 20         | Firewall updated to block unauthorized IPs |

### **Targets**

| Username      | Attempts |
| ------------- | -------- |
| Administrator | 9,315    |
| ADMINISTRATOR | 958      |
| ADMIN         | 339      |
| USER          | 307      |
| ADMINISTRADOR | 69       |
| USUARIO       | 51       |

---

## 🛡️ Detection Rule

### **Brute Force Detection SPL**

```spl
index=dmensah-ad sourcetype=WinEventLog EventCode=4625
| bucket _time span=3m
| stats count as failed_attempts, values(Account_Name) as targeted_accounts, dc(Account_Name) as unique_accounts by _time, Source_Network_Address, host
| where failed_attempts >= 10
| sort - failed_attempts
```

### **Alert Configuration**

| Setting           | Value                           |
| ----------------- | ------------------------------- |
| Trigger Condition | failed_attempts ≥ 10            |
| Time Window       | 3 minutes                       |
| Schedule          | Every 5 minutes                 |
| Severity          | High                            |
| Purpose           | Detect RDP brute force attempts |

---

## 📊 Dashboard

| Panel                           | Type         | Goal                       |
| ------------------------------- | ------------ | -------------------------- |
| Failed Login Attempts Over Time | Line Chart   | Identify spikes            |
| Top Attacking IPs               | Bar Chart    | Show hostile sources       |
| Targeted Account Distribution   | Pie Chart    | Identify targeted users    |
| Attack by Hour                  | Column Chart | Reveal attacker behavior   |

---

## 🛠️ Installation Guide

### **Requirements**

| Component | Minimum                          |
| --------- | -------------------------------- |
| VMs       | 1× Ubuntu, 2× Windows Servers    |
| Splunk    | Enterprise (free dev license ok) |
| AD        | 1 domain controller              |
| Sysmon    | Latest version                   |

### **Setup Steps**

| Step | Action                                    |
| ---- | ----------------------------------------- |
| 1    | Install Splunk Enterprise                 |
| 2    | Build AD domain                           |
| 3    | Install Splunk UF on Windows servers      |
| 4    | Configure input stanzas for 4624/4625     |
| 5    | Deploy Sysmon with SwiftOnSecurity config |
| 6    | Configure brute force alert               |
| 7    | Build 4-panel dashboard                   |


---

## 🎓 Lessons Learned

| Lesson             | Description                                  |
| ------------------ | -------------------------------------------- |
| SIEM Deployment    | Installed Splunk in a real cloud environment |
| Log Engineering    | Collected & normalized Windows + Sysmon logs |
| Incident Detection | Detected a real brute force attack           |
| Dashboarding       | Built data-driven security visuals           |
| Incident Response  | Investigated & mitigated a live threat       |

---

## 🚀 Future Enhancements

| Enhancement                | Benefit                               |
| -------------------------- | ------------------------------------- |
| Add more detection rules   | Catch credential dumping, C2 activity |
| Integrate Suricata or Zeek | Add network telemetry                 |
| Add SOAR automation        | Auto-block attacker IPs               |
| Deploy honeypot accounts   | Track targeted activity               |
| Add Linux log sources      | Expand enterprise coverage            |


