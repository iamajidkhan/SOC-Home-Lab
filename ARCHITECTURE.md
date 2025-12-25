# 🏗️ SOC Lab Architecture Documentation

**Enterprise-Grade Security Operations Center on AWS**

---

## 📑 Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Infrastructure Components](#infrastructure-components)
4. [Network Architecture](#network-architecture)
5. [Security Architecture](#security-architecture)
6. [Data Flow Architecture](#data-flow-architecture)
7. [VPC Traffic Mirroring](#vpc-traffic-mirroring)
8. [Security Groups Configuration](#security-groups-configuration)
9. [Active Directory Structure](#active-directory-structure)
10. [Design Decisions & Rationale](#design-decisions--rationale)
11. [Scalability & Future Enhancements](#scalability--future-enhancements)

---

## Executive Summary

This SOC Lab demonstrates a production-grade security operations infrastructure deployed on AWS, featuring a comprehensive defense-in-depth architecture with centralized SIEM, endpoint detection and response (EDR), network intrusion detection (IDS), and Active Directory domain services. The lab environment showcases enterprise security monitoring capabilities across 5 EC2 instances in the Asia Pacific (Sydney) region.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Cloud Platform** | AWS (ap-southeast-2 - Sydney) |
| **Total EC2 Instances** | 5 |
| **VPC CIDR Block** | 172.31.0.0/16 |
| **Availability Zones** | 2 (ap-southeast-2a, ap-southeast-2c) |
| **Security Groups** | 5 (layered network security) |
| **Detection Rules** | 6 (MITRE ATT&CK mapped) |
| **Security Dashboards** | 5 (70 visualization panels) |
| **VPC Traffic Mirroring** | 3 sources → 1 IDS target |

---

## Architecture Overview

### High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AWS Region: ap-southeast-2 (Sydney)                   │
│                              VPC: 172.31.0.0/16                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────┐        ┌───────────────────────────────────┐
│   Availability Zone: 2a       │        │   Availability Zone: 2c           │
│   Subnet: 03db897332fa4f9ae   │        │   Subnet: 070255697ea11536f      │
│                               │        │                                   │
│  ┌─────────────────────────┐  │        │  ┌─────────────────────────────┐ │
│  │  WINDOWS DC - Server    │  │        │  │  Splunk-SIEM-Server         │ │
│  │  172.31.8.11            │  │        │  │  172.31.31.157              │ │
│  │  t3.small               │  │        │  │  15.134.167.115 (Elastic)   │ │
│  │  Domain: majidlab.local │  │        │  │  c7i-flex.large             │ │
│  └──────────┬──────────────┘  │        │  └──────────┬──────────────────┘ │
│             │                  │        │             │                    │
│  ┌──────────▼──────────────┐  │        └─────────────┼────────────────────┘
│  │  Majid-Workstation      │  │                      │
│  │  172.31.1.40            │  │                      │
│  │  t3.small               │  │        ┌─────────────▼──────────────────┐
│  │  Windows 11 Client      │  │        │     Internet Gateway           │
│  └──────────┬──────────────┘  │        │     (Elastic IPs)              │
│             │                  │        └────────────────────────────────┘
│  ┌──────────▼──────────────┐  │
│  │  Wazuh-EDR              │  │                      │
│  │  172.31.2.109           │  │                      │
│  │  3.105.219.127 (Elastic)│  │        ┌─────────────▼──────────────────┐
│  │  c7i-flex.large         │  │        │     Admin Workstation          │
│  └──────────┬──────────────┘  │        │     136.185.74.16/32          │
│             │                  │        │     (Management Access)        │
│  ┌──────────▼──────────────┐  │        └────────────────────────────────┘
│  │  Suricata-Sensor        │  │
│  │  172.31.15.151          │  │
│  │  t3.small               │  │        ┌────────────────────────────────┐
│  │  IDS/IPS Engine         │  │────────│  VPC Traffic Mirror Target     │
│  └─────────────────────────┘  │        │  Receives mirrored traffic     │
│                               │        │  from DC, Workstation, Wazuh   │
└───────────────────────────────┘        └────────────────────────────────┘
```

### Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Cloud Infrastructure** | AWS EC2, VPC | Compute and network foundation |
| **SIEM** | Splunk Enterprise 10.0.2 | Centralized log aggregation and correlation |
| **EDR** | Wazuh 4.7.5 | Endpoint detection, FIM, vulnerability scanning |
| **IDS/IPS** | Suricata 8.0.2 | Network-based intrusion detection |
| **Directory Services** | Active Directory 2022 | Identity and access management |
| **Endpoint Monitoring** | Sysmon 15.15 | Windows event enrichment |
| **Network Capture** | VPC Traffic Mirroring | Packet-level network visibility |

---

## Infrastructure Components

### 1. Splunk-SIEM-Server

**Purpose**: Centralized Security Information and Event Management (SIEM) platform

**Specifications:**
- **Instance Type**: c7i-flex.large (compute-optimized)
- **vCPUs**: 2
- **Memory**: 8 GiB
- **Private IP**: 172.31.31.157
- **Public IP**: 15.134.167.115 (Elastic IP)
- **Availability Zone**: ap-southeast-2c
- **Subnet**: subnet-070255697ea11536f
- **Operating System**: Ubuntu 22.04 LTS

**Key Functions:**
- Splunk Web UI on port 8000
- Universal Forwarder ingestion on port 9997 (from DC, Workstation, Wazuh, Suricata)
- Splunk Management API on port 8089
- Hosts 5 security dashboards with 70 visualization panels
- Executes 6 custom detection rules
- Stores 90 days of indexed security event data

**Data Sources:**
- Windows Event Logs (DC, Workstation)
- Sysmon logs (process, network, file activity)
- Suricata IDS alerts and flow data
- Wazuh EDR alerts and agent health

---

### 2. Wazuh-EDR

**Purpose**: Endpoint Detection and Response (EDR) platform with security agent management

**Specifications:**
- **Instance Type**: c7i-flex.large (compute-optimized)
- **vCPUs**: 2
- **Memory**: 8 GiB
- **Private IP**: 172.31.2.109
- **Public IP**: 3.105.219.127 (Elastic IP)
- **Availability Zone**: ap-southeast-2a
- **Subnet**: subnet-03db897332fa4f9ae
- **Operating System**: Ubuntu 22.04 LTS

**Key Functions:**
- Wazuh Manager for agent orchestration
- File Integrity Monitoring (FIM) across all endpoints
- Vulnerability detection with CVE correlation
- Security Configuration Assessment (SCA)
- Compliance monitoring (CIS benchmarks)
- Agents deployed on Windows DC and Workstation

**Integration:**
- Forwards EDR alerts to Splunk via Universal Forwarder (port 9997)
- Monitors agent health across domain environment
- Real-time threat detection and response
- Wazuh agents report to Manager via ports 1514/1515

---

### 3. WINDOWS DC - Server

**Purpose**: Active Directory Domain Controller for majidlab.local domain

**Specifications:**
- **Instance Type**: t3.small (general purpose)
- **vCPUs**: 2
- **Memory**: 2 GiB
- **Private IP**: 172.31.8.11
- **Public IP**: None (internal access only)
- **Availability Zone**: ap-southeast-2a
- **Subnet**: subnet-03db897332fa4f9ae
- **Operating System**: Windows Server 2022 Datacenter

**Key Functions:**
- Active Directory Domain Services (AD DS)
- DNS Server for majidlab.local domain
- Group Policy Object (GPO) management
- Centralized authentication (Kerberos, NTLM)
- LDAP directory services
- Domain-joined workstation management

**Security Configuration:**
- Sysmon deployed via GPO
- Advanced audit policy enabled
- PowerShell script block logging enabled
- Process creation logging (Event ID 4688)
- Splunk Universal Forwarder for log collection
- Wazuh agent for EDR monitoring

---

### 4. Majid-Workstation

**Purpose**: SOC analyst workstation and attack simulation endpoint

**Specifications:**
- **Instance Type**: t3.small (general purpose)
- **vCPUs**: 2
- **Memory**: 2 GiB
- **Private IP**: 172.31.1.40
- **Public IP**: None (internal access only)
- **Availability Zone**: ap-southeast-2a
- **Subnet**: subnet-03db897332fa4f9ae
- **Operating System**: Windows 11 Pro

**Key Functions:**
- Domain-joined to majidlab.local
- RDP access for SOC operations
- Attack simulation and detection testing
- PowerShell execution for threat hunting
- Lateral movement testing endpoint

**Security Configuration:**
- Sysmon for endpoint telemetry
- Splunk Universal Forwarder
- Wazuh agent for FIM and vulnerability scanning
- Enhanced PowerShell logging
- Network traffic mirrored to Suricata

---

### 5. Suricata-Sensor

**Purpose**: Network-based Intrusion Detection System (IDS)

**Specifications:**
- **Instance Type**: t3.small (general purpose)
- **vCPUs**: 2
- **Memory**: 2 GiB
- **Private IP**: 172.31.15.151
- **Public IP**: None (internal access only)
- **Availability Zone**: ap-southeast-2a
- **Subnet**: subnet-03db897332fa4f9ae
- **Operating System**: Ubuntu 22.04 LTS

**Key Functions:**
- VPC Traffic Mirror target (eni-0ddfacb4c81ccd744)
- Receives mirrored traffic from DC, Workstation, and Wazuh
- IDS-only mode (alerts without blocking)
- 63,022 Emerging Threats (ET Open) signatures
- Protocol analysis and anomaly detection
- JSON event logging (eve.json)

**Network Capture:**
- Monitors traffic via VXLAN (port 4789)
- Processes VPC-mirrored packets in real-time
- Forwards IDS alerts to Splunk (port 9997)
- Captures bi-directional traffic flows

---

## Network Architecture

### VPC Configuration

**VPC Details:**
- **VPC CIDR**: 172.31.0.0/16 (65,536 available IPs)
- **Region**: ap-southeast-2 (Asia Pacific - Sydney)
- **Availability Zones**: 2 (ap-southeast-2a, ap-southeast-2c)
- **Subnets**: 2 (high availability design)

**Subnet Distribution:**

| Subnet ID | CIDR | AZ | Instances |
|-----------|------|----|-----------| 
| subnet-03db897332fa4f9ae | /20 | ap-southeast-2a | DC, Workstation, Wazuh, Suricata (4) |
| subnet-070255697ea11536f | /20 | ap-southeast-2c | Splunk (1) |

**Design Rationale:**
- Splunk isolated in separate AZ for fault tolerance
- Core domain infrastructure (DC, Workstation) co-located in AZ-2a for low latency
- Security sensors (Wazuh, Suricata) in same AZ as endpoints for efficient monitoring

### IP Address Allocation

| Instance | Private IP | Subnet | Purpose |
|----------|------------|--------|---------|
| Splunk-SIEM-Server | 172.31.31.157 | /20 | SIEM platform |
| Wazuh-EDR | 172.31.2.109 | /20 | EDR management |
| WINDOWS DC | 172.31.8.11 | /20 | Domain controller |
| Majid-Workstation | 172.31.1.40 | /20 | Analyst workstation |
| Suricata-Sensor | 172.31.15.151 | /20 | IDS sensor |

### Elastic IP Assignment

**Public-Facing Services:**
- **Splunk-SIEM-Server**: 15.134.167.115 (administrative access to Splunk Web UI)
- **Wazuh-EDR**: 3.105.219.127 (Wazuh dashboard and API access)

**Internal-Only Services:**
- Domain Controller, Workstation, Suricata (no direct internet exposure)

### SSH Access Configuration

**Key Pair**: splunk-key (RSA 2048-bit)
- **Created**: 2025-11-22
- **Fingerprint**: 01:85:14:d0:6d:46:6a:0c:ab:8e:8
- **Used For**: SSH access to Splunk, Wazuh, Suricata servers
- **Access Control**: Restricted to admin IP 136.185.74.16/32

---

## Security Architecture

### Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Network Security (AWS Security Groups)                 │
│ • Least-privilege firewall rules                                │
│ • Source IP restrictions                                        │
│ • Protocol-specific access control                              │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│ Layer 2: Network Detection (Suricata IDS)                       │
│ • 63,022 ET Open signatures                                     │
│ • VPC Traffic Mirroring                                         │
│ • Protocol anomaly detection                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│ Layer 3: Endpoint Detection (Wazuh + Sysmon)                    │
│ • File Integrity Monitoring                                     │
│ • Process execution monitoring                                  │
│ • Registry modification tracking                                │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│ Layer 4: Log Aggregation & Correlation (Splunk)                 │
│ • Centralized SIEM                                              │
│ • 6 custom detection rules                                      │
│ • 5 operational dashboards                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────────┐
│ Layer 5: Identity & Access Management (Active Directory)        │
│ • Centralized authentication                                    │
│ • Group Policy enforcement                                      │
│ • Audit logging                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Security Monitoring Coverage

| Layer | Technology | Coverage |
|-------|------------|----------|
| **Network** | Suricata IDS, VPC Traffic Mirroring | All traffic between DC, Workstation, Wazuh |
| **Endpoint** | Sysmon, Wazuh Agents | Process, file, registry, network activity |
| **Identity** | Windows Event Logs, AD Auditing | Authentication, authorization, privilege use |
| **Application** | PowerShell Logging, Script Block Logging | Command execution, obfuscation attempts |
| **Correlation** | Splunk SIEM | Cross-layer threat detection and investigation |

---

## Data Flow Architecture

### Log Collection Flow

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         LOG COLLECTION PIPELINE                             │
└────────────────────────────────────────────────────────────────────────────┘

Windows DC (172.31.8.11)
  │
  ├──[Sysmon Events]────────────────────┐
  ├──[Windows Event Logs]───────────────┤
  ├──[PowerShell Logs]──────────────────┤
  ├──[Wazuh Agent: 1514]────────────────┼──► Wazuh EDR (172.31.2.109:1514)
  │                                      │
  └──[Splunk UF: 9997]──────────────────┼─────► Splunk SIEM (172.31.31.157:9997)
                                         │
Windows Workstation (172.31.1.40)       │
  │                                      │
  ├──[Sysmon Events]────────────────────┤
  ├──[Windows Event Logs]───────────────┤
  ├──[PowerShell Logs]──────────────────┤
  ├──[Wazuh Agent: 1514/1515]───────────┼──► Wazuh EDR (172.31.2.109:1514)
  │                                      │
  └──[Splunk UF: 9997]──────────────────┤
                                         │
Wazuh EDR (172.31.2.109)                │
  │ Receives from Wazuh Agents:         │
  │ • DC (172.31.8.11)                  │
  │ • Workstation (172.31.1.40)         │
  │                                      │
  ├──[Wazuh Alerts]─────────────────────┤
  ├──[Agent Health]─────────────────────┤
  ├──[FIM Alerts]───────────────────────┤
  ├──[Vulnerability Scan Results]───────┤
  ├──[SCA Findings]─────────────────────┤
  │                                      │
  └──[Splunk UF: 9997]──────────────────┤
                                         │
Suricata IDS (172.31.15.151)            │
  │                                      │
  ├──[IDS Alerts]───────────────────────┤
  ├──[Flow Data]────────────────────────┤
  ├──[Protocol Analysis]────────────────┤
  │                                      │
  └──[Splunk UF: 9997]──────────────────┘
                                         
                        │
                        ▼
        ┌───────────────────────────────┐
        │   Splunk Indexers              │
        │   • Windows Index              │
        │   • Wazuh Index                │
        │   • Suricata Index             │
        └───────────────────────────────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │   Search & Correlation         │
        │   • 6 Detection Rules          │
        │   • 5 Dashboards               │
        │   • Ad-hoc Investigations      │
        └───────────────────────────────┘
```

### Network Traffic Flow

```
┌──────────────────────────────────────────────────────────────────────┐
│                     NETWORK TRAFFIC PATTERNS                          │
└──────────────────────────────────────────────────────────────────────┘

Admin Workstation (136.185.74.16/32)
  │
  ├──[RDP: 3389]────────────────────►  Windows DC (172.31.8.11)
  ├──[RDP: 3389]────────────────────►  Workstation (172.31.1.40)
  ├──[SSH: 22]──────────────────────►  Splunk (172.31.31.157)
  ├──[SSH: 22]──────────────────────►  Wazuh (172.31.2.109)
  ├──[SSH: 22]──────────────────────►  Suricata (172.31.15.151)
  ├──[HTTPS: 8000]──────────────────►  Splunk Web UI
  └──[HTTPS: 443]───────────────────►  Wazuh Web UI

Windows Workstation (172.31.1.40)
  │
  ├──[LDAP: 389]────────────────────►  Windows DC (172.31.8.11)
  ├──[Kerberos: 88]─────────────────►  Windows DC (172.31.8.11)
  ├──[SMB: 445]─────────────────────►  Windows DC (172.31.8.11)
  ├──[DNS: 53]──────────────────────►  Windows DC (172.31.8.11)
  ├──[Wazuh Agent: 1514/1515]───────►  Wazuh EDR (172.31.2.109)
  └──[Splunk UF: 9997]──────────────►  Splunk (172.31.31.157)

Windows DC (172.31.8.11)
  │
  ├──[Wazuh Agent: 1514]────────────►  Wazuh EDR (172.31.2.109)
  └──[Splunk UF: 9997]──────────────►  Splunk (172.31.31.157)

Wazuh EDR (172.31.2.109)
  │
  ├──[Splunk UF: 9997]──────────────────►  Splunk (172.31.31.157)
  └──[Wazuh API: 55000]◄────────────────   Workstation (172.31.1.40)

Suricata IDS (172.31.15.151)
  │
  ├──[Mirror Traffic: 4789]◄────────   VPC Traffic Mirror
  └──[Splunk UF: 9997]──────────────►  Splunk (172.31.31.157)
```

---

## VPC Traffic Mirroring

### Overview

VPC Traffic Mirroring provides cloud-native packet capture capabilities, enabling Suricata IDS to perform deep packet inspection of network traffic without requiring physical network taps or inline deployment.

### Configuration Details

**Mirror Target:**
- **Name**: Suricata-Mirror-Target
- **Target ID**: tmt-0715c1364e4eec9a5
- **Type**: Network Interface
- **Destination**: eni-0ddfacb4c81ccd744 (Suricata-Sensor)
- **ENI IP**: 172.31.15.151

**Mirror Sessions (3 Active):**

| Session Name | Source ENI | Source IP | Session Number | Filter |
|--------------|-----------|-----------|----------------|--------|
| DC01 | eni-0d47c396bed84ae36 | 172.31.8.11 | 1 | tmf-0c9891d42a9ad954a |
| Workstation | eni-05a6ef8e995794b06 | 172.31.1.40 | 2 | tmf-0c9891d42a9ad954a |
| wazuh server | eni-04029f0f97c9b8523 | 172.31.2.109 | 3 | tmf-0c9891d42a9ad954a |

**Mirror Filter Configuration:**

**Filter Name**: Suricata-Mirror-Filter  
**Filter ID**: tmf-0c9891d42a9ad954a

**Inbound Rules:**
- **Rule 100**: Accept all protocols from 0.0.0.0/0 to 0.0.0.0/0

**Outbound Rules:**
- **Rule 100**: Accept all protocols from 0.0.0.0/0 to 0.0.0.0/0

**Capture Scope**: Bidirectional traffic (inbound + outbound)

### Traffic Mirroring Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                VPC TRAFFIC MIRRORING DATA FLOW                  │
└────────────────────────────────────────────────────────────────┘

Windows DC (172.31.8.11)
  │  All Network Traffic
  │  ─────────────────────────────────┐
  │                                    │
  ├──[Normal Routing]───────────────► Destination
  │                                    │
  └──[Mirrored Copy]────────┐         │
                            │         │
Windows Workstation         │         │
  │  All Network Traffic    │         │
  │  ───────────────────────┼─────────┤
  │                         │         │
  ├──[Normal Routing]───────┼────────►│
  │                         │         │
  └──[Mirrored Copy]────────┤         │
                            │         │
Wazuh EDR (172.31.2.109)    │         │
  │  All Network Traffic    │         │
  │  ───────────────────────┼─────────┤
  │                         │         │
  ├──[Normal Routing]───────┼────────►│
  │                         │         │
  └──[Mirrored Copy]────────┤         │
                            │         │
                            ▼         │
        ┌────────────────────────────┐│
        │  VPC Traffic Mirror Target ││
        │  (Suricata-Sensor)         ││
        │  172.31.15.151:4789 (VXLAN)││
        │  tmt-0715c1364e4eec9a5     ││
        └────────────────────────────┘│
                    │                 │
                    ▼                 │
        ┌────────────────────────────┐│
        │  Suricata IDS Engine       ││
        │  • VXLAN decapsulation     ││
        │  • Signature matching      ││
        │  • Protocol analysis       ││
        │  • Anomaly detection       ││
        └────────────────────────────┘│
                    │                 │
                    ▼                 │
        ┌────────────────────────────┐│
        │  IDS Alerts → Splunk       ││
        │  eve.json (JSON format)    ││
        └────────────────────────────┘│
                                      │
                                      ▼
                            Original Traffic Flow
                            Continues Unmodified
```

### Key Benefits

✅ **Non-Intrusive**: Mirroring doesn't impact production traffic  
✅ **Zero Latency**: No inline inspection delays  
✅ **Comprehensive Coverage**: Captures all protocols and ports  
✅ **Cloud-Native**: No hardware taps or SPAN ports required  
✅ **Scalable**: Can add/remove mirror sources dynamically  

---

## Security Groups Configuration

### Security Group Architecture

Each instance has a dedicated security group implementing least-privilege access control. Security groups act as stateful firewalls, controlling inbound and outbound traffic at the network interface level.

### 1. Splunk-SIEM-Server Security Group

**SG ID**: sg-04cd57c9514255482  
**Instance**: Splunk-SIEM-Server (15.134.167.115, 172.31.31.157)

#### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | 22 | 136.185.74.16/32 | Admin SSH access |
| TCP | 8000 | 136.185.74.16/32 | Splunk Web UI (restricted to admin) |
| TCP | 9997 | 172.31.2.109/32 | Splunk Universal Forwarder (Wazuh logs) |
| TCP | 9997 | 172.31.8.11/32 | Splunk Universal Forwarder (DC logs) |
| TCP | 9997 | 172.31.1.40/32 | Splunk Universal Forwarder (Workstation logs) |
| TCP | 9997 | 172.31.15.151/32 | Splunk Universal Forwarder (Suricata logs) |
| TCP | 8089 | 0.0.0.0/0 | Splunk Management/API (Universal Forwarder auth) |

#### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| ALL | ALL | 0.0.0.0/0 | Responses, updates, threat intelligence integrations |

**Security Considerations:**
- Splunk Web UI restricted to admin IP only (not 0.0.0.0/0)
- Each log source explicitly allowed (least privilege)
- Port 8089 open to 0.0.0.0/0 to support Universal Forwarder certificate-based authentication

---

### 2. Wazuh-EDR Security Group

**SG ID**: sg-0de004a9773725a07  
**Instance**: Wazuh-EDR (3.105.219.127, 172.31.2.109)

#### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | 1514 | 172.31.8.11/32 | Wazuh agent logs (DC) |
| TCP | 1514 | 172.31.0.0/16 | Wazuh agent ingestion (VPC-wide) |
| TCP | 1515 | 172.31.0.0/16 | Agent registration and authentication |
| TCP | 1515 | 172.31.1.40/32 | Agent communication (Workstation) |
| TCP | 55000 | 172.31.1.40/32 | Wazuh API access (from Workstation) |
| TCP | 55000 | 172.31.0.0/16 | Internal API access (VPC-wide) |
| TCP | 443 | 0.0.0.0/0 | Wazuh Web UI (HTTPS) |
| TCP | 22 | 136.185.74.16/32 | Admin SSH access |

#### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| ALL | ALL | 0.0.0.0/0 | General outbound (updates, responses) |
| TCP | 9997 | 172.31.31.157/32 | Forward Wazuh logs to Splunk via Universal Forwarder |

**Security Considerations:**
- Port 1514/1515 allow VPC-wide agent connections (agents authenticate via certificates)
- Wazuh API (55000) accessible from Workstation for management operations
- Web UI open to internet (protected by authentication)
- Splunk Universal Forwarder sends Wazuh alerts to Splunk SIEM

---

### 3. WINDOWS DC - Server Security Group

**SG ID**: sg-02a1dd598bdb82625  
**Instance**: WINDOWS DC - Server (172.31.8.11)

#### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | 0-65535 | 172.31.0.0/16 | RPC dynamic port range (AD replication) |
| TCP | 135 | 172.31.0.0/16 | RPC Endpoint Mapper |
| TCP | 445 | 172.31.0.0/16 | SMB (SYSVOL, NETLOGON shares) |
| TCP | 389 | 172.31.0.0/16 | LDAP directory queries |
| UDP | 389 | 172.31.0.0/16 | LDAP directory queries |
| TCP | 636 | 172.31.0.0/16 | LDAPS (LDAP over SSL) |
| TCP | 88 | 172.31.0.0/16 | Kerberos authentication |
| UDP | 88 | 172.31.0.0/16 | Kerberos authentication |
| TCP | 53 | 172.31.0.0/16 | DNS queries |
| UDP | 53 | 172.31.0.0/16 | DNS queries |
| ICMP | ALL | 172.31.2.109/32 | Reachability testing from Wazuh |
| ALL | ALL | sg-0b0d786ecd8f90a39 | Trust relationship with Workstation SG |
| TCP | 3389 | 136.185.74.16/32 | RDP administrative access |
| TCP | 5985 | 136.185.74.16/32 | WinRM HTTP (remote management) |
| TCP | 5986 | 136.185.74.16/32 | WinRM HTTPS (remote management) |

#### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| ALL | ALL | 0.0.0.0/0 | AD responses, replication, updates |

**Security Considerations:**
- Comprehensive Active Directory port coverage (LDAP, Kerberos, SMB, DNS)
- Security group trust relationship with Workstation (sg-0b0d786ecd8f90a39)
- RPC dynamic ports required for AD operations
- RDP/WinRM restricted to admin IP only

---

### 4. Majid-Workstation Security Group

**SG ID**: sg-0b0d786ecd8f90a39  
**Instance**: Majid-Workstation (172.31.1.40)

#### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| ICMP | ALL | 172.31.2.109/32 | Connectivity testing from Wazuh |
| ALL | ALL | sg-02a1dd598bdb82625 | Trust relationship with Domain Controller SG |
| TCP | 3389 | 136.185.74.16/32 | RDP access for SOC operations |
| TCP | 5985 | 136.185.74.16/32 | WinRM HTTP |
| TCP | 5986 | 136.185.74.16/32 | WinRM HTTPS |

#### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| ALL | ALL | 0.0.0.0/0 | Analyst workstation outbound access |

**Security Considerations:**
- Bidirectional trust with Domain Controller security group
- RDP restricted to admin IP
- Full outbound access for analyst operations and threat hunting

---

### 5. Suricata-Sensor Security Group

**SG ID**: sg-0213cf8914a720a14  
**Instance**: Suricata-Sensor (172.31.15.151)

#### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | 22 | 136.185.74.16/32 | Admin SSH access |
| ALL | ALL | 172.31.0.0/16 | Receive VPC-mirrored traffic (VXLAN port 4789) |

#### Outbound Rules

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| ALL | ALL | 0.0.0.0/0 | Send IDS alerts to Splunk, signature updates |

**Security Considerations:**
- Permissive inbound from VPC (required to receive VXLAN-encapsulated mirrored traffic)
- SSH restricted to admin IP
- IDS sensor has no listening services exposed to internet

---

## Active Directory Structure

### Domain Configuration

**Domain Name**: majidlab.local  
**Forest Functional Level**: Windows Server 2022  
**Domain Controller**: MAJID-DC01 (172.31.8.11)

### Organizational Units (OUs)

```
majidlab.local
│
├── Domain Controllers
│   └── MAJID-DC01
│
├── Computers
│   └── Majid-Workstation
│
├── Users
│   ├── Administrator (Domain Admin)
│   └── Standard Users
│
└── Security Groups
    ├── Domain Admins
    ├── SOC Analysts
    └── Workstation Users
```

### Group Policy Objects (GPOs)

**Applied GPOs:**

1. **Sysmon Deployment GPO**
   - Deploys Sysmon 15.15 via startup script
   - Configures SwiftOnSecurity Sysmon config
   - Applied to: Domain Controllers, Workstations

2. **Advanced Audit Policy GPO**
   - Enables detailed security event logging
   - Process creation auditing (4688)
   - Privilege use auditing (4672)
   - Account management auditing (4720, 4728, 4732, 4756)

3. **PowerShell Logging GPO**
   - Script Block Logging enabled
   - Module Logging enabled
   - Transcription logging enabled
   - Applied to: All domain computers

### Domain Security Features

✅ **Kerberos Authentication** - Secure ticket-based authentication  
✅ **Group Policy Enforcement** - Centralized security configuration  
✅ **Audit Logging** - Comprehensive event tracking (Event IDs 4624, 4625, 4672, 4688, 4720)  
✅ **SMB Signing** - Prevents relay attacks  
✅ **LDAPS** - Encrypted directory queries  

---

## Design Decisions & Rationale

### Cloud Platform Selection

**Decision**: AWS (ap-southeast-2 - Sydney)

**Rationale:**
- Geographic proximity for low latency
- Comprehensive security services (VPC Traffic Mirroring, Security Groups)
- Elastic IP support for persistent public endpoints
- Cost-effective instance types (t3.small for sensors, c7i-flex.large for compute-intensive workloads)

### Instance Sizing Strategy

| Workload Type | Instance Selection | Reasoning |
|---------------|-------------------|-----------|
| **SIEM (Splunk)** | c7i-flex.large | Compute-optimized for search operations, 8GB RAM for indexing |
| **EDR (Wazuh)** | c7i-flex.large | Compute-optimized for agent management and log processing |
| **Domain Services** | t3.small | General-purpose, AD is not CPU-intensive |
| **Workstation** | t3.small | Sufficient for analyst operations and attack simulation |
| **IDS (Suricata)** | t3.small | Network inspection is moderate CPU usage |

### Multi-AZ Deployment

**Decision**: Splunk in ap-southeast-2c, other instances in ap-southeast-2a

**Rationale:**
- Splunk isolation improves fault tolerance (SIEM remains operational if one AZ fails)
- Core infrastructure (DC, Workstation, sensors) co-located for minimal latency
- Cost balance between high availability and expense (full multi-AZ duplication not required for lab)

### VPC Traffic Mirroring vs. Inline IDS

**Decision**: VPC Traffic Mirroring with Suricata in IDS-only mode

**Rationale:**
- **Zero Performance Impact**: Mirroring doesn't add latency to production traffic
- **Scalability**: Can add/remove mirror sources without network reconfiguration
- **Flexibility**: IDS mode allows alert-only operation (no blocking) for testing
- **Cloud-Native**: Leverages AWS-native capabilities (no virtual appliances required)

**Trade-off**: IDS-only mode means no real-time blocking (acceptable for lab/detection-focused environment)

### Centralized Logging Architecture

**Decision**: Splunk as central SIEM (vs. distributed logging)

**Rationale:**
- **Single Pane of Glass**: All telemetry sources aggregate to one platform
- **Correlation Capability**: Cross-source detection rules (e.g., correlate network IDS alerts with endpoint process execution)
- **Retention Management**: Centralized 90-day retention policy
- **Search Performance**: Optimized indexing for fast investigations

### Security Group Granularity

**Decision**: One security group per instance (vs. shared security groups)

**Rationale:**
- **Least Privilege**: Each instance has minimal required access
- **Change Isolation**: Modifying one instance's rules doesn't affect others
- **Clear Ownership**: Security group name matches instance name for clarity
- **Auditability**: Easy to review each instance's attack surface

### Domain-Joined Workstation

**Decision**: Windows 11 Pro workstation joined to majidlab.local domain

**Rationale:**
- **Realistic Environment**: Mirrors enterprise setup with centralized identity management
- **GPO Testing**: Validates Sysmon and logging policy deployment via Group Policy
- **Attack Simulation**: Enables lateral movement and domain-based attack scenarios
- **Authentication Logging**: Generates Event IDs 4624, 4625 for authentication monitoring

---

## Scalability & Future Enhancements

### Planned Enhancements

**Phase 2 - Advanced Detection:**
- Add 4 additional detection rules (total: 10)
- Implement machine learning-based anomaly detection
- Deploy SOAR playbooks for automated response

**Phase 3 - Threat Intelligence:**
- Integrate MISP threat intelligence platform
- Add threat feed correlation to detection rules
- Implement reputation-based blocking (IP/domain blocklists)

**Phase 4 - Cloud Security:**
- Deploy AWS CloudTrail for API auditing
- Implement AWS GuardDuty for cloud-native threat detection
- Add VPC Flow Logs for comprehensive network visibility

**Phase 5 - Compliance & Reporting:**
- Implement CIS benchmark compliance dashboards
- Add automated compliance reporting (NIST, PCI DSS)
- Create executive-level KPI dashboards

### Scalability Considerations

**Horizontal Scaling:**
- Splunk indexer clustering (add more indexers for higher log volume)
- Wazuh manager clustering (multi-node Wazuh deployment)
- Suricata load balancing (multiple IDS sensors for high throughput)

**Vertical Scaling:**
- Upgrade Splunk to c7i.xlarge (16GB RAM) for larger data retention
- Increase Wazuh memory for higher agent counts (100+ agents)

**Cost Optimization:**
- Use AWS Savings Plans for committed usage discounts
- Implement S3 archival for older Splunk data (cost reduction)
- Schedule non-production instances to stop during off-hours

---

## Network Diagram (Detailed)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AWS VPC: 172.31.0.0/16 (ap-southeast-2)                   │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Availability Zone: ap-southeast-2a (subnet-03db897332fa4f9ae)         │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │  WINDOWS DC - Server (172.31.8.11)                               │ │ │
│  │  │  • Active Directory Domain Services                              │ │ │
│  │  │  • DNS Server (majidlab.local)                                   │ │ │
│  │  │  • Sysmon + Wazuh Agent + Splunk UF                              │ │ │
│  │  │  • VPC Traffic Mirroring Source                                  │ │ │
│  │  └────────────────┬─────────────────────────────────────────────────┘ │ │
│  │                   │ LDAP/Kerberos/SMB/DNS                             │ │
│  │  ┌────────────────▼─────────────────────────────────────────────────┐ │ │
│  │  │  Majid-Workstation (172.31.1.40)                                 │ │ │
│  │  │  • Domain-Joined Windows 11                                      │ │ │
│  │  │  • Sysmon + Wazuh Agent + Splunk UF                              │ │ │
│  │  │  • VPC Traffic Mirroring Source                                  │ │ │
│  │  └────────────────┬─────────────────────────────────────────────────┘ │ │
│  │                   │                                                    │ │
│  │  ┌────────────────▼─────────────────────────────────────────────────┐ │ │
│  │  │  Wazuh-EDR (172.31.2.109 | 3.105.219.127)                        │ │ │
│  │  │  • Wazuh Manager (Agents: DC, Workstation)                       │ │ │
│  │  │  • File Integrity Monitoring                                     │ │ │
│  │  │  • Vulnerability Scanning                                        │ │ │
│  │  │  • VPC Traffic Mirroring Source                                  │ │ │
│  │  │  • Forwards to Splunk HEC (8088)                                 │ │ │
│  │  └────────────────┬─────────────────────────────────────────────────┘ │ │
│  │                   │                                                    │ │
│  │  ┌────────────────▼─────────────────────────────────────────────────┐ │ │
│  │  │  Suricata-Sensor (172.31.15.151)                                 │ │ │
│  │  │  • VPC Traffic Mirror Target (VXLAN 4789)                        │ │ │
│  │  │  • Suricata IDS (63,022 ET signatures)                           │ │ │
│  │  │  • Receives mirrored traffic from: DC, Workstation, Wazuh        │ │ │
│  │  │  • Forwards to Splunk UF (9997)                                  │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Availability Zone: ap-southeast-2c (subnet-070255697ea11536f)         │ │
│  │                                                                        │ │
│  │  ┌──────────────────────────────────────────────────────────────────┐ │ │
│  │  │  Splunk-SIEM-Server (172.31.31.157 | 15.134.167.115)             │ │ │
│  │  │  • Splunk Enterprise 10.0.2                                      │ │ │
│  │  │  • Receives logs from: DC, Workstation, Suricata, Wazuh          │ │ │
│  │  │  • 5 Dashboards, 6 Detection Rules                               │ │ │
│  │  │  • 90-day retention                                              │ │ │
│  │  └──────────────────────────────────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │  Internet Gateway                                                      │ │
│  │  • Elastic IPs: Splunk (15.134.167.115), Wazuh (3.105.219.127)        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │  Admin Workstation            │
                      │  136.185.74.16/32            │
                      │  • SSH to Linux instances     │
                      │  • RDP to Windows instances   │
                      │  • Splunk Web UI access       │
                      │  • Wazuh Web UI access        │
                      └───────────────────────────────┘
```

---

## Conclusion

This SOC Lab demonstrates enterprise-grade security architecture with comprehensive visibility across network, endpoint, and identity layers. The infrastructure showcases:

✅ **Cloud-Native Design**: Leveraging AWS services (VPC Traffic Mirroring, Security Groups, Elastic IPs)  
✅ **Defense-in-Depth**: Multiple security layers (network IDS, EDR, SIEM, IAM)  
✅ **Centralized Operations**: Splunk SIEM as single pane of glass for all security telemetry  
✅ **Production-Ready**: Mirrors real-world enterprise SOC operations and workflows  
✅ **Scalable Architecture**: Designed for horizontal and vertical scaling as needed  

The lab provides hands-on experience with modern SOC technologies and demonstrates practical skills in detection engineering, incident response, threat hunting, and security operations.

---

## Related Documentation

- [README.md](./README.md) - Project overview and quick start
- [DASHBOARDS.md](./DASHBOARDS.md) - Security dashboard documentation (70 panels across 5 dashboards)
- [DETECTION-RULES.md](./DETECTION-RULES.md) - Detection rule documentation (6 rules with SPL queries)

---

## Contact & Portfolio Links

**Author**: Majid Khan  
**LinkedIn**: [linkedin.com/in/iamajidkhan](https://www.linkedin.com/in/iamajidkhan)  
**GitHub**: [github.com/iamajidkhan](https://github.com/iamajidkhan)  
**Project Repository**: [SOC-Home-Lab](https://github.com/iamajidkhan/SOC-Home-Lab)

---

**Last Updated**: December 2024  
**Version**: 1.0  
**Status**: Production-Ready SOC Lab Environment
