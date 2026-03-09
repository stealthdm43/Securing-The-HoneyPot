# Securing an Insecure Azure Honeypot VM (Bastion + Hardening + Sentinel Alerts)

## Overview
This lab **secures a previously insecure Azure Windows 10 VM** that was originally configured as an exposed “honeypot” (public-facing and intentionally vulnerable for observation).<a href="https://github.com/stealthdm43/Honeypot-Homelab">The original Honeypot Lab</a>  

In this project, the VM is hardened by:
- removing direct public exposure
- enforcing access via **Azure Bastion**
- tightening **NSG inbound rules**
- enabling Windows host protections (**Firewall**, **NLA**, **account lockout policy**)
- creating **Microsoft Sentinel scheduled analytics rules** (alerts + incidents)

---



## Hardening Steps (What Changed)

### 1) Removed the VM Public IP (No direct internet reachability)
![Public IP Removed](https://i.imgur.com/VkfCtXO.png)

### 2) Restricted inbound RDP to the Virtual Network (Bastion-compatible)
RDP (3389) is allowed only from the **VirtualNetwork** service tag (no public RDP).
![NSG VNetOnly RDP](https://i.imgur.com/OiKSsNa.png)

### 3) Enabled Windows Defender Firewall (Domain/Private/Public ON)
![Firewall On](https://i.imgur.com/tDMnq12.png)

### 4) Required Network Level Authentication (NLA) for RDP
![NLA Required](https://i.imgur.com/HxpkEYY.png)

### 5) Least-privilege access: non-admin user for remote access
Non-admin user added to **Remote Desktop Users** group.
![Remote Desktop Users Group](https://i.imgur.com/klaL7Jz.png)

### 6) Enabled Account Lockout Policy (to disrupt brute forcing)
![Account Lockout Policy](https://i.imgur.com/CkI3T2O.png)

### 7) Enforced secure access via Azure Bastion
RDP access is performed through the Azure portal using Bastion.
![Azure Bastion Login](https://i.imgur.com/kADrgdu.png)

Example validation (access denied during lockout/testing):
![Connection Denied](https://i.imgur.com/UTpBmzr.png)

---

## Sentinel Alerts (Scheduled Analytics Rules)

These detections are configured as **Scheduled query rules** in Microsoft Sentinel and set to **Create incidents** when they return results.

Rule configuration + schedule proof:
![Rules + Config](https://i.imgur.com/FQqCNAP.png)

Incident proof (rule fired → incident created):
![Incident Details](https://i.imgur.com/s1xPTzB.png)

Incident/alert activity view:
![Incidents + Alerts Graph](https://i.imgur.com/DJdBwyu.png)

---

## Sentinal Scheduled Rules Set Up

> Tip: In Sentinel → Analytics → Create → **Scheduled query rule**
- Run query every: **5–10 minutes**
- Lookup data from last: **5–10 minutes**
- Trigger alert if results: **greater than 0**
- Enable: **Create incidents from this rule**
### Query For Rule 1
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count(),
          FirstSeen = min(TimeGenerated),
          LastSeen = max(TimeGenerated)
  by IpAddress, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 20
| project TimeGenerated, IpAddress, Computer, FailedAttempts, FirstSeen, LastSeen
```
### Query For Rule 2
```kql
SecurityEvent
| where EventID == 4625
| extend SrcIP = iff(isempty(IpAddress), "UNKNOWN", IpAddress)
| summarize FailedAttempts = count(),
          FirstSeen = min(TimeGenerated),
          LastSeen  = max(TimeGenerated)
  by SrcIP, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 20
| project TimeGenerated, SrcIP, Computer, FailedAttempts, FirstSeen, LastSeen
| order by TimeGenerated desc
```
### Query For Rule 3
```kql
SecurityEvent
| where EventID == 4625
| extend SrcIP = iff(isempty(IpAddress), "UNKNOWN", IpAddress)
| summarize UsersTargeted = dcount(TargetUserName),
          Attempts       = count(),
          SampleUsers    = make_set(TargetUserName, 10),
          FirstSeen      = min(TimeGenerated),
          LastSeen       = max(TimeGenerated)
  by SrcIP, Computer, bin(TimeGenerated, 10m)
| where UsersTargeted > 8 and Attempts > 15
| project TimeGenerated, SrcIP, Computer, UsersTargeted, Attempts, SampleUsers, FirstSeen, LastSeen
| order by TimeGenerated desc
```
