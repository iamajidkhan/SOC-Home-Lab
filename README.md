# 🔐 Enterprise SOC Home Lab
**Cloud-Native Security Operations Center on AWS**

[![AWS](https://img.shields.io/badge/AWS-EC2-orange?logo=amazon-aws)](https://aws.amazon.com/)
[![Splunk](https://img.shields.io/badge/Splunk-10.0.2-green?logo=splunk)](https://www.splunk.com/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.5-blue?logo=wazuh)](https://wazuh.com/)
[![Suricata](https://img.shields.io/badge/Suricata-8.0.2-red?logo=suricata)](https://suricata.io/)
[![Sysmon](https://img.shields.io/badge/Sysmon-15.15-yellow)](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Active Directory](https://img.shields.io/badge/Active_Directory-2022-blue?logo=windows)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

---

## 📋 Table of Contents
- [Executive Summary](#executive-summary)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Detection Capabilities](#detection-capabilities)
- [Security Dashboards](#security-dashboards)
- [Active Directory Structure](#active-directory-structure)
- [Group Policy Objects](#group-policy-objects)
- [Skills Demonstrated](#skills-demonstrated)
- [Setup Guide](#setup-guide)
- [About This Project](#About-This-Project)
- [Documentation](#documentation)

---

## 🎯 Executive Summary

**Enterprise-grade Security Operations Center (SOC) home lab** built on AWS infrastructure, demonstrating comprehensive cybersecurity monitoring, threat detection, and incident response capabilities. This project showcases practical experience with industry-standard SIEM, EDR, IDS/IPS, and endpoint monitoring tools in a production-like environment.

### **Key Achievements:**
- ✅ **6 Detection Rules** covering the complete cyber kill chain (MITRE ATT&CK framework)
- ✅ **5 Security Dashboards** with 70+ visualization panels for threat hunting and incident response
- ✅ **Multi-layered Defense Architecture** (SIEM + EDR + IDS/IPS + Endpoint Monitoring)
- ✅ **Active Directory Domain** with 12 security-hardened Group Policy Objects
- ✅ **VPC Traffic Mirroring** for comprehensive network visibility
- ✅ **Automated Threat Detection** with near-real-time alerting
- ✅ **Complete Documentation** suitable for enterprise SOC operations

### **Purpose:**
This lab serves as both a learning environment and a professional portfolio piece, demonstrating hands-on expertise in:
- Security Operations Center (SOC) operations
- Threat detection and incident response
- SIEM administration and use case development
- Endpoint detection and response (EDR)
- Network intrusion detection systems (IDS/IPS)
- Active Directory security hardening
- Cloud security architecture on AWS

---

## 🏗️ Architecture

### **High-Level Design**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          AWS VPC (ap-southeast-2)                            │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                    Subnet: 172.31.0.0/16 (AZ 2a)                      │  │
│  │                                                                        │  │
│  │  ┌─────────────────┐      ┌─────────────────┐      ┌──────────────┐  │  │
│  │  │  MAJID-DC01     │      │ WIN-CLIENT02    │      │ Wazuh-EDR    │  │  │
│  │  │  Domain Ctrl    │◄────►│  Workstation    │◄────►│  Manager     │  │  │
│  │  │  172.31.8.11    │      │  172.31.1.40    │      │ 172.31.2.109 │  │  │
│  │  │                 │      │                 │      │              │  │  │
│  │  │  - AD DS        │      │  - Domain       │      │  - Wazuh Mgr │  │  │
│  │  │  - DNS Server   │      │    Joined       │      │  - Dashboard │  │  │
│  │  │  - GPO Control  │      │  - Sysmon       │      │  - API       │  │  │
│  │  │  - Sysmon       │      │  - Splunk UF    │      │              │  │  │
│  │  │  - Splunk UF    │      │  - Wazuh Agent  │      │              │  │  │
│  │  │  - Wazuh Agent  │      │                 │      │              │  │  │
│  │  └────────┬────────┘      └────────┬────────┘      └──────┬───────┘  │  │
│  │           │                        │                       │          │  │
│  │           │    Traffic Mirror      │    Traffic Mirror     │          │  │
│  │           └────────┬───────────────┴────────┬──────────────┘          │  │
│  │                    │                        │                         │  │
│  │                    ▼                        ▼                         │  │
│  │           ┌──────────────────────────────────────┐                   │  │
│  │           │      Suricata-Sensor (IDS/IPS)       │                   │  │
│  │           │         172.31.15.151                │                   │  │
│  │           │                                      │                   │  │
│  │           │  - Suricata 8.0.2 (ET Open Rules)   │                   │  │
│  │           │  - Traffic Mirror Target (VXLAN)     │                   │  │
│  │           │  - Network Flow Analysis             │                   │  │
│  │           └──────────────┬───────────────────────┘                   │  │
│  │                          │                                           │  │
│  └──────────────────────────┼───────────────────────────────────────────┘  │
│                             │                                              │
│  ┌──────────────────────────┼───────────────────────────────────────────┐  │
│  │       Isolated Subnet (AZ 2c)                                        │  │
│  │                          │                                           │  │
│  │                          ▼                                           │  │
│  │           ┌──────────────────────────────┐                          │  │
│  │           │   Splunk-SIEM-Server         │                          │  │
│  │           │   172.31.31.157              │                          │  │
│  │           │   (EIP: 15.134.167.115)      │                          │  │
│  │           │                              │                          │  │
│  │           │  - Splunk Enterprise 10.0.2  │                          │  │
│  │           │  - 6 Detection Rules         │                          │  │
│  │           │  - 5 Security Dashboards     │                          │  │
│  │           │  - SIEM Analysis             │                          │  │
│  │           └──────────────────────────────┘                          │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

                                    │
                                    ▼
                        ┌───────────────────────┐
                        │    Analyst Access     │
                        │   (My IP: Allowed)    │
                        │                       │
                        │  - Splunk Web UI      │
                        │  - Wazuh Dashboard    │
                        │  - RDP to Endpoints   │
                        │  - SSH to Linux       │
                        └───────────────────────┘
```

### **Infrastructure Components**

| Component | Type | IP Address | Role | Key Software |
|-----------|------|------------|------|--------------|
| **Splunk-SIEM-Server** | t3.small (Ubuntu 22.04) | 172.31.31.157 | SIEM/Analytics | Splunk Enterprise 10.0.2 |
| **MAJID-DC01** | t3.small (Windows Server 2022) | 172.31.8.11 | Domain Controller | AD DS, Sysmon 15.15, Splunk UF, Wazuh Agent |
| **WIN-CLIENT02** | t3.small (Windows Server 2022) | 172.31.1.40 | Workstation | Sysmon 15.15, Splunk UF, Wazuh Agent |
| **Wazuh-EDR** | c7i-flex.large (Ubuntu 22.04) | 172.31.2.109 | EDR Manager | Wazuh Manager 4.7.5 |
| **Suricata-Sensor** | t3.small (Ubuntu 22.04) | 172.31.15.151 | IDS/IPS | Suricata 8.0.2 (ET Open Rules) |

### **Network Security**
- **VPC Traffic Mirroring**: All traffic from DC, Workstation, and Wazuh mirrored to Suricata for IDS analysis
- **Security Groups**: Layered firewall rules controlling access between components
- **Network Segmentation**: SIEM server isolated in separate subnet for security
- **Elastic IPs**: Public access to Splunk and Wazuh dashboards

---

## 🛠️ Technologies Used

### **SIEM Platform**
- **Splunk Enterprise 10.0.2** - Centralized log aggregation and analysis
- **Splunk Universal Forwarder 10.0.2** - Log collection from Windows endpoints

### **Endpoint Detection & Response**
- **Wazuh Manager 4.7.5** - EDR platform (server)
- **Wazuh Agent 4.7.5** - Endpoint agents
- **Sysmon 15.15** - Advanced Windows endpoint telemetry (SwiftOnSecurity config)

### **Network Detection**
- **Suricata 8.0.2** - IDS/IPS engine
- **ET Open Ruleset** - 63,022+ community threat signatures
- **AWS VPC Traffic Mirroring** - Network TAP for comprehensive visibility

### **Infrastructure**
- **AWS EC2** - Virtual machine hosting (5 instances)
- **Amazon VPC** - Virtual private cloud networking
- **Security Groups** - Network access control
- **EBS Volumes** - Persistent storage (8-50 GiB per instance)

### **Identity & Access Management**
- **Active Directory Domain Services** - Domain: majidlab.local
- **Group Policy Objects** - 12 security hardening GPOs
- **Windows Server 2022** - Domain controller and workstation OS
- **Ubuntu 22.04** - Linux server OS

---

## 🎯 Detection Capabilities

### **6 Detection Rules Covering the Cyber Kill Chain**

All detection rules map to the **MITRE ATT&CK framework** and provide near-real-time alerting with severity classification.

| # | Detection Rule | MITRE Technique | Tactic | Severity | Description |
|---|----------------|-----------------|--------|----------|-------------|
| **1** | **Brute Force Authentication Detection** | T1110 | Initial Access | HIGH | Detects 5+ failed login attempts within 15 minutes, identifying credential stuffing and password spraying attacks |
| **2** | **Suspicious PowerShell Execution** | T1059.001 | Execution | CRITICAL | Identifies encoded commands, download cradles, Invoke-Expression, and bypass execution policy flags |
| **3** | **Lateral Movement Detection** | T1021 | Lateral Movement | HIGH | Monitors network logons (Type 3) and administrative logons (Type 10) across systems, tracking attacker spreading |
| **4** | **Privilege Escalation Detection** | T1068, T1078 | Privilege Escalation | CRITICAL | Detects suspicious privilege assignments (SeDebugPrivilege, SeImpersonatePrivilege) and admin account usage |
| **5** | **C2 Beaconing Detection** | T1071 | Command & Control | HIGH | Statistical analysis of network connections identifying consistent periodic communication patterns to external IPs |
| **6** | **New Admin Account Creation** | T1136.001/.002 | Persistence | CRITICAL | Monitors account creation (Event 4720) and additions to privileged groups with risk-based severity scoring |

### **Detection Coverage by Kill Chain Phase**

```
Initial Access → Execution → Persistence → Privilege Escalation → Lateral Movement → C2
     ✅              ✅           ✅                 ✅                    ✅          ✅
 (Detection #1) (Detection #2) (Detection #6)    (Detection #4)     (Detection #3) (Detection #5)
  Brute Force    PowerShell    Account Creation  Privilege Use      Network Logon  Beaconing
```

### **Key Detection Features**
- ✅ **Statistical Anomaly Detection** (C2 beaconing, account behavior)
- ✅ **Behavioral Analysis** (process execution patterns, network timing)
- ✅ **Threshold-based Alerting** (brute force attempts, privilege escalation)
- ✅ **Correlation Logic** (multi-event attack chains)
- ✅ **Severity Scoring** (CRITICAL, HIGH, MEDIUM based on risk)
- ✅ **False Positive Reduction** (account type classification, time windows)

---

## 📊 Security Dashboards

### **5 Comprehensive Dashboards (70+ Total Panels)**

#### **Dashboard 1: Security Operations Overview** (13 Panels)
**Purpose**: Real-time SOC monitoring for triage and response  
**Features**:
- Critical metrics: Failed logins, new accounts, privilege escalations, lateral movement events
- Recent alerts timeline (last 50)
- Top targeted accounts
- Geographic source IP distribution
- Systems with most alerts
- Alert severity distribution
- Scheduled task creations
- Service installations

#### **Dashboard 2: Threat Hunting Dashboard** (13 Panels)
**Purpose**: Proactive threat hunting through behavioral analysis  
**Features**:
- **Process Execution Analysis**: Rare processes, suspicious directories, unsigned executables, encoded PowerShell
- **Network Anomalies**: Rare destination IPs, non-standard ports, external connections by system
- **User Behavior**: Off-hours authentication, failed login trends, statistical anomaly detection
- **Persistence Mechanisms**: Recent scheduled tasks, new services, registry modifications

**Hunting Methodology**: Hypothesis-driven investigation using frequency analysis, location-based detection, and statistical outlier identification

#### **Dashboard 3: Incident Response Dashboard** (15 Panels)
**Purpose**: Active incident investigation and response  
**Features**:
- **Incident Overview**: Active incident count, MITRE techniques detected, affected systems, incident duration
- **Attack Timeline**: Chronological event reconstruction, technique frequency over time
- **Evidence Collection**: Process execution chains, network connections, file system modifications
- **MITRE ATT&CK Mapping**: Techniques by tactic, detailed breakdown, kill chain progression
- **Containment**: Account activity summary, systems requiring isolation, response actions log

**IR Lifecycle Support**: Detection → Investigation → Containment → Eradication → Recovery

#### **Dashboard 4: Endpoint Security Dashboard** (18 Panels)
**Purpose**: Endpoint health monitoring and threat detection  
**Features**:
- Security metrics (Sysmon events, Wazuh alerts, process creations, network connections)
- Process execution analysis
- File integrity monitoring
- Network activity tracking
- Registry modifications
- Authentication patterns
- Vulnerability detection
- System inventory

#### **Dashboard 5: Network Traffic Analysis Dashboard** (11 Panels)
**Purpose**: Network security monitoring and anomaly detection  
**Features**:
- Network overview metrics
- Traffic volume by protocol
- Top talkers (source/destination IPs)
- Suricata alerts by severity
- Geographic traffic distribution
- Port utilization
- Alert timeline
- Threat signatures triggered
- DNS query analysis
- HTTP/HTTPS traffic breakdown

---

## 🏢 Active Directory Structure

### **Domain: majidlab.local**

```
majidlab.local (Forest/Domain)
│
├── 00-Administration
│   ├── AdminUsers (Domain Admins)
│   ├── Helpdesk (IT Support)
│   └── ServiceAccounts (Service Principals)
│
├── 01-Users
│   ├── Attackers → [Attacker User]
│   ├── SOCUsers → [SOC Analyst]
│   └── StandardUsers → [John Doe, Sarah Khan]
│
├── 02-Computers
│   ├── LabMachines
│   ├── Servers
│   │   ├── ApplicationServers
│   │   ├── DomainControllers
│   │   ├── LinuxServers
│   │   └── SecurityTools (EDR, IDS-IPS, Proxy, WAF)
│   └── Workstations → [WIN-CLIENT02]
│
├── 03-GPO (Group Policy Objects)
│   ├── SecurityHardening
│   ├── ServerPolicies
│   ├── SOCPolicies
│   └── WorkstationPolicies
│
├── 04-SOC (Security Operations)
│   ├── Honeypots
│   ├── Splunk
│   ├── Sysmon
│   └── ThreatIntel
│
└── 05-Groups
    ├── DistributionGroups
    └── SecurityGroups
```

### **Domain Users (5 Created)**
1. **Raju Admin** - Domain Administrator (Administrators group)
2. **Attacker User** - Simulated threat actor account (Attackers OU)
3. **SOC Analyst** - Security analyst account (SOCUsers OU)
4. **John Doe** - Standard user (StandardUsers OU)
5. **Sarah Khan** - Standard user (StandardUsers OU)

### **Domain Computers**
- **WIN-CLIENT02** - Domain-joined Windows workstation (Workstations OU)
- **MAJID-DC01** - Domain controller

---

## 🔒 Group Policy Objects

### **12 Security-Hardened GPOs**

| GPO Name | Purpose | Key Settings | Linked OU |
|----------|---------|--------------|-----------|
| **GPO-Server-AuditPolicies** | Enable deep security auditing | Account Logon, Kerberos, Object Access, Policy Change, Privilege Use | Servers |
| **GPO-Server-DefenderSecurity** | Harden servers with Defender + ASR | Real-time Protection, Cloud Protection, ASR rules (LSASS protection, Office child processes) | Servers |
| **GPO-Server-Hardening** | Reduce server attack surface | Disable SMBv1/LLMNR/NetBIOS, Enforce NTLMv2, Strong passwords | Servers |
| **GPO-SOC-EDR-Deploy** | Deploy Wazuh Agent automatically | MSI deployment, Startup registration script | Servers, Workstations |
| **GPO-SOC-SplunkUF-Deploy** | Install Splunk Universal Forwarder | MSI deployment, Configure outputs/indexes | Servers, Workstations |
| **GPO-SOC-SysmonConfigDeploy** | Deploy Sysmon with config | Install Sysmon, Apply sysmon.xml, Enable Event IDs 1,3,7,10,11,22 | Servers, Workstations |
| **GPO-Workstation-DefenderSecurity** | Enforce endpoint security | Defender real-time protection, ASR rules, Controlled Folder Access | Workstations |
| **GPO-Workstation-Hardening** | Harden workstations | Disable SMBv1/LLMNR/NetBIOS, Block unsigned PowerShell, Disable macros | Workstations |
| **GPO-Workstation-PowerShellLogging** | Enable PowerShell telemetry | Script Block Logging, Module Logging, Transcription | Workstations |
| **GPO-Workstation-RDP-Allow** | Controlled RDP access | Allow RDP, Restrict to security groups, Enable NLA | Workstations |
| **GPO-Workstation-Sysmon** | Ensure Sysmon service running | Automatic startup, Prevent tampering | Workstations |
| **GPO-Workstation-WindowsEventLogging** | Enable Windows Event IDs | Increased log sizes, Security/System/Application logs, Detailed logon auditing | Workstations |

### **GPO Architecture Benefits**
- ✅ **Automated Deployment**: Sysmon, Splunk UF, and Wazuh Agent deploy automatically via GPO
- ✅ **Centralized Management**: All security configurations managed from Domain Controller
- ✅ **Consistent Hardening**: Uniform security posture across all endpoints
- ✅ **Comprehensive Logging**: Maximum telemetry for threat detection and IR
- ✅ **Attack Surface Reduction**: Disabled legacy protocols and risky services

---

## 💡 Skills Demonstrated

### **Security Operations Center (SOC) Skills**
- ✅ **SIEM Administration**: Splunk deployment, configuration, index management
- ✅ **Use Case Development**: 6 production-grade detection rules with correlation logic
- ✅ **Dashboard Creation**: 5 operational dashboards with 70+ visualization panels
- ✅ **Threat Hunting**: Hypothesis-driven hunting using behavioral analytics
- ✅ **Incident Response**: Complete IR lifecycle from detection to recovery
- ✅ **Alert Tuning**: False positive reduction through contextual analysis

### **Threat Detection & Analysis**
- ✅ **MITRE ATT&CK Framework**: Technique mapping and kill chain analysis
- ✅ **Statistical Analysis**: Anomaly detection using standard deviation and frequency analysis
- ✅ **Behavioral Analytics**: Process execution patterns, network timing analysis
- ✅ **Correlation Logic**: Multi-event attack chain detection
- ✅ **Log Analysis**: Windows Event Logs, Sysmon, network flows, EDR telemetry

### **Endpoint Security**
- ✅ **EDR Deployment**: Wazuh Manager and Agent configuration
- ✅ **Sysmon Configuration**: SwiftOnSecurity config implementation
- ✅ **File Integrity Monitoring**: Critical system file tracking
- ✅ **Process Monitoring**: Suspicious execution detection
- ✅ **Registry Monitoring**: Persistence mechanism detection

### **Network Security**
- ✅ **IDS/IPS Implementation**: Suricata deployment with ET Open rules
- ✅ **Network Traffic Analysis**: Flow analysis, protocol distribution, anomaly detection
- ✅ **VPC Traffic Mirroring**: Cloud-native network TAP configuration
- ✅ **Packet Inspection**: Deep packet analysis for threat detection

### **Cloud & Infrastructure**
- ✅ **AWS EC2**: Instance deployment, sizing, optimization
- ✅ **VPC Networking**: Subnet design, security groups, traffic mirroring
- ✅ **Infrastructure as Code**: Documented, repeatable architecture
- ✅ **Cost Optimization**: Right-sizing instances, efficient resource usage

### **Active Directory & Windows**
- ✅ **AD DS Administration**: Domain setup, OU design, user/computer management
- ✅ **Group Policy**: 12 GPOs for security hardening and tool deployment
- ✅ **Windows Security**: Audit policies, event log configuration
- ✅ **PowerShell Logging**: Script block logging, transcription, module logging

### **Technical Documentation**
- ✅ **Architecture Documentation**: Complete infrastructure diagrams and specifications
- ✅ **Runbook Creation**: Detection rules, dashboards, configuration files
- ✅ **Troubleshooting Guides**: Common issues and resolutions
- ✅ **Interview Preparation**: Technical talking points and Q&A

---

## 📚 Setup Guide

### **Prerequisites**
- AWS Account with EC2, VPC access
- Basic understanding of Windows Server, Active Directory, Linux
- Familiarity with SIEM concepts and log analysis

### **High-Level Build Process**

1. **Infrastructure Setup** (2-3 hours)
   - Deploy 5 EC2 instances on AWS
   - Configure VPC, subnets, security groups
   - Set up VPC Traffic Mirroring

2. **Active Directory Configuration** (1-2 hours)
   - Promote DC, create domain majidlab.local
   - Design OU structure
   - Create users and groups

3. **Security Tool Deployment** (3-4 hours)
   - Install Splunk Enterprise on SIEM server
   - Deploy Wazuh Manager
   - Configure Suricata IDS/IPS
   - Install Sysmon on Windows endpoints

4. **Group Policy Implementation** (2-3 hours)
   - Create 12 security GPOs
   - Link GPOs to appropriate OUs
   - Force policy updates

5. **SIEM Configuration** (4-6 hours)
   - Configure Splunk Universal Forwarders
   - Set up indexes and data inputs
   - Create 6 detection rules
   - Build 5 security dashboards

6. **Testing & Validation** (2-3 hours)
   - Run attack simulations
   - Validate detection rules trigger
   - Test dashboard functionality
   - Document findings

**Total Build Time**: Approximately 2-3 weeks (full-time effort)

### **Detailed Setup Documentation**
See [SETUP-GUIDE.md](./SETUP-GUIDE.md) for step-by-step instructions.

---
## 💡 About This Project

This Security Operations Center home lab was built to gain hands-on experience with enterprise-grade security operations in a cloud environment. The project demonstrates practical application of threat detection, incident response, and security monitoring concepts that are essential in modern SOC environments.

### Project Goals

- **Practical Experience**: Deploy and configure enterprise security tools (SIEM, EDR, IDS/IPS) in a production-like environment
- **Detection Engineering**: Develop sophisticated correlation rules covering the complete cyber kill chain
- **Threat Hunting**: Build proactive monitoring capabilities using statistical analysis and behavioral detection
- **Cloud Security**: Understand AWS security architecture, including VPC networking, Security Groups, and traffic mirroring
- **Documentation**: Practice creating professional technical documentation for security infrastructure and detection logic

### Key Achievements

- Built a multi-layered defense architecture with network, endpoint, and centralized monitoring
- Developed 6 production-ready detection rules mapped to MITRE ATT&CK framework
- Created 5 comprehensive security dashboards with 70+ visualization panels
- Configured Active Directory domain with security-hardened Group Policy Objects
- Implemented automated security tool deployment via GPO for scalable endpoint management
- Successfully tested all detection rules with simulated attack scenarios

This lab demonstrates understanding of enterprise security operations, from infrastructure deployment through threat detection and incident response workflows. All components are documented with detailed technical specifications and detection logic explanations.

---

## 📖 Documentation

### **Available Documentation Files**

- **[README.md](./README.md)** - This file (project overview)
- **[ARCHITECTURE.md](./ARCHITECTURE.md)** - Detailed infrastructure documentation
- **[SETUP-GUIDE.md](./SETUP-GUIDE.md)** - Step-by-step build instructions
- **[DETECTION-RULES.md](./DETECTION-RULES.md)** - Complete detection rule documentation
- **[DASHBOARDS.md](./DASHBOARDS.md)** - All dashboard specifications
- **[GPO-CONFIGURATION.md](./GPO-CONFIGURATION.md)** - Group Policy Object details
- **[INTERVIEW-GUIDE.md](./INTERVIEW-GUIDE.md)** - Comprehensive interview preparation
- **[TROUBLESHOOTING.md](./TROUBLESHOOTING.md)** - Common issues and solutions

### **Configuration Files**

- **[configs/splunk/](./configs/splunk/)** - Splunk inputs.conf, outputs.conf, props.conf
- **[configs/sysmon/](./configs/sysmon/)** - Sysmon configuration XML (SwiftOnSecurity)
- **[configs/wazuh/](./configs/wazuh/)** - Wazuh ossec.conf
- **[configs/suricata/](./configs/suricata/)** - Suricata YAML configuration

### **Detection Rules**

- **[detections/](./detections/)** - All 6 detection rules as .spl files

### **Dashboards**

- **[dashboards/](./dashboards/)** - All 5 dashboard XML exports

---

## 🎓 Skills & Certifications

**Relevant for SOC Analyst Positions:**
- Security Information and Event Management (SIEM)
- Endpoint Detection and Response (EDR)
- Intrusion Detection/Prevention Systems (IDS/IPS)
- Incident Response & Forensics
- Threat Hunting
- MITRE ATT&CK Framework
- Log Analysis (Windows Event Logs, Sysmon)
- Network Traffic Analysis
- Active Directory Security
- Cloud Security (AWS)

---

## 📞 Contact

**LinkedIn**: https://www.linkedin.com/in/abdul-majid-khan-b14ab7220/
**GitHub**: https://github.com/iamajidkhan
**Email**: abdulmajidkhan.career@gmail.com

---

## 📜 License

This project is documented for educational and portfolio purposes. Feel free to reference the architecture and methodologies, but please provide attribution if you use significant portions of the documentation or detection logic.

---

## 🙏 Acknowledgments

- **SwiftOnSecurity** - Sysmon configuration template
- **Splunk Community** - Detection rule examples and best practices
- **MITRE ATT&CK** - Threat framework and technique mapping
- **Emerging Threats** - Suricata community ruleset
- **Wazuh Team** - EDR platform and documentation

---

**⭐ If this project helped you prepare for SOC analyst interviews or learn security monitoring, please star the repository!**

---

**Last Updated**: December 2025  
**Project Status**: Complete & Production-Ready  
**Build Time**: ~3 weeks (full-time effort)
