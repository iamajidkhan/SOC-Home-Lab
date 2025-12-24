# 📊 SOC Lab Security Dashboards

This document provides detailed technical documentation for the five production-grade security dashboards built in Splunk Enterprise as part of my SOC Home Lab. Each dashboard demonstrates comprehensive security monitoring capabilities across different operational domains.

---

## 📑 Table of Contents

1. [Security Operations Overview Dashboard](#1-security-operations-overview-dashboard)
2. [Threat Hunting Dashboard](#2-threat-hunting-dashboard)
3. [Incident Response Dashboard](#3-incident-response-dashboard)
4. [Endpoint Security Dashboard](#4-endpoint-security-dashboard)
5. [Network Traffic Analysis Dashboard](#5-network-traffic-analysis-dashboard)

---

## 1. Security Operations Overview Dashboard

### Purpose
Executive-level security posture dashboard providing real-time visibility into detection rule performance, threat landscape, and data collection health across the SOC Lab infrastructure.

### Key Features
- **13 Panels**: 8 single-value KPIs, 2 visualization charts, 3 data tables
- **Auto-refresh**: Every 5 minutes
- **Time Range**: Last 24 hours (adjustable)
- **Data Sources**: Windows Event Logs, Suricata IDS, Splunk Internal Logs

### Technical Capabilities

#### Detection Rule Monitoring
- Tracks execution of 5 custom correlation rules covering the cyber kill chain
- Real-time visibility into alert trigger frequency and detection health
- Automated detection rule performance metrics (execution count, first/last run times)

#### Data Collection Validation
- **Suricata Events**: Network traffic monitoring via VPC Traffic Mirroring
- **Windows Events**: Comprehensive endpoint log collection (authentication, privileges, processes)
- Operational health checks ensuring no blind spots in security telemetry

#### Visual Analytics
- **Alert Frequency by Detection Type**: Bar chart ranking detection rule activity
- **Alert Triggers Over Time**: Timeline visualization showing attack progression patterns
- **Top Event Sources**: System-level event distribution analysis

### What This Demonstrates
- **SPL Expertise**: Complex Splunk queries with statistical aggregation and field normalization
- **Security Operations**: Understanding of SOC operational metrics and detection infrastructure monitoring
- **Executive Communication**: Color-coded severity indicators and at-a-glance security posture assessment
- **Detection Engineering**: Custom correlation rules mapped to MITRE ATT&CK framework

---

## 2. Threat Hunting Dashboard

### Purpose
Proactive threat hunting workspace enabling security analysts to find hidden threats through behavioral analysis, statistical anomaly detection, and frequency-based threat identification.

### Key Features
- **13 Panels**: 4 anomaly metrics, 3 behavioral charts, 6 investigation tables
- **Auto-refresh**: Every 10 minutes
- **Time Range**: Last 24 hours (adjustable)
- **Data Sources**: Sysmon, Suricata, Windows Event Logs

### Technical Capabilities

#### Behavioral Analysis
- **Rare Process Detection**: Frequency analysis identifying executables with <5 occurrences (potential malware)
- **Suspicious Directory Execution**: Processes running from temp/download folders
- **Unsigned Binary Tracking**: Code signing validation for executable authenticity

#### Network Anomaly Detection
- **Rare Destination IPs**: Statistical frequency analysis surfacing potential C2 infrastructure
- **Non-Standard Ports**: Identifies custom backdoors and C2 channels on unusual ports
- **External Connection Profiling**: Ranks systems by internet-bound traffic volume

#### User Behavior Analytics
- **Off-Hours Authentication**: Detects login activity during 6 PM - 6 AM and weekends
- **Failed Login Aggregation**: Identifies accounts under brute force attack
- **Statistical Anomaly Detection**: Flags accounts >2 standard deviations from baseline

#### Persistence Mechanisms
- **Scheduled Task Monitoring**: Tracks creation of Windows Task Scheduler entries
- **Service Installation Detection**: Monitors new Windows services for backdoor persistence
- **Registry Modification Tracking**: Alerts on Run keys and Winlogon changes

### What This Demonstrates
- **Threat Hunting Methodology**: Hypothesis-driven hunting using behavioral indicators
- **Statistical Analysis**: Standard deviation calculations and frequency-based anomaly detection
- **MITRE ATT&CK Knowledge**: Comprehensive persistence mechanism coverage
- **Data Science Skills**: Behavioral baselines and statistical threshold detection

---

## 3. Incident Response Dashboard

### Purpose
Centralized incident response workspace providing comprehensive tools for active incident investigation, attack timeline reconstruction, MITRE ATT&CK technique tracking, and containment action monitoring.

### Key Features
- **15 Panels**: 4 incident metrics, 3 charts, 8 investigation tables
- **Auto-refresh**: Every 15 minutes
- **Time Range**: Last 7 days (comprehensive incident scope)
- **Data Sources**: Windows Event Logs, Suricata, Sysmon

### Technical Capabilities

#### Incident Scoping
- **Active Incidents Count**: Tracks distinct detection rules triggered (incident types)
- **MITRE Techniques Detected**: Maps activity to ATT&CK framework for sophistication assessment
- **Affected Systems**: Counts unique endpoints involved (lateral movement scope)
- **Incident Duration**: Calculates days elapsed since first critical alert

#### Attack Timeline Reconstruction
- **Chronological Events Table**: Time-ordered security events showing complete attack progression
- **Technique Frequency Over Time**: Visualizes when different MITRE techniques occurred
- Enables identification of attack phases and prediction of next attacker moves

#### Evidence Collection
- **Suspicious Process Execution Chain**: Parent-child process relationships revealing attack vectors
- **Network Connections from Affected Systems**: Identifies C2 communication and lateral movement
- **File System Modifications**: Tracks malware drops and data staging

#### MITRE ATT&CK Integration
- **Techniques by Tactic**: Bar chart showing event volume per ATT&CK tactic
- **Detailed Technique Breakdown**: Complete mapping of events to specific techniques (e.g., T1110, T1068)
- **Kill Chain Stage Progression**: Identifies furthest stage attacker reached (1-11 scale)

#### Containment & Response
- **Account Activity Summary**: Authentication patterns identifying compromised credentials
- **Systems Requiring Isolation**: Automated containment recommendations based on alert volume
- **Response Actions Log**: Chronological audit trail of all response actions taken

### What This Demonstrates
- **Incident Response Expertise**: Complete IR lifecycle from detection through recovery
- **MITRE ATT&CK Proficiency**: Automated technique mapping and kill chain analysis
- **Forensic Analysis**: Timeline reconstruction and evidence correlation
- **Decision-Making Frameworks**: Risk-based containment prioritization and automated recommendations

---

## 4. Endpoint Security Dashboard

### Purpose
Comprehensive endpoint monitoring providing real-time visibility into process behavior, PowerShell forensics, file operations, registry modifications, and host-based threat detection through Sysmon and Wazuh EDR integration.

### Key Features
- **18 Panels**: 15 Sysmon behavioral + 3 Wazuh EDR compliance
- **Auto-refresh**: Every 5 minutes
- **Time Range**: Last 24 hours (adjustable)
- **Data Sources**: Sysmon, Windows Event Logs, Wazuh EDR

### Technical Capabilities

#### Process Execution Monitoring
- **Behavioral Scoring**: Requires BOTH suspicious binary AND malicious command pattern
- **Rare Process Detection**: Identifies infrequently executed binaries (potential attacker tools)
- **Process Creation Timeline**: Visualizes execution patterns categorized by process type
- **Unsigned Executable Tracking**: Code signing validation with suspicious location analysis

#### PowerShell Forensics
- **Suspicious Command Categorization**: Automatic threat classification (Encoded, Download Cradle, Credential Theft)
- **Encoded PowerShell Detection**: Regex extraction of Base64 payloads with parent process context
- **Per-User Profiling**: Benign vs. suspicious PowerShell execution comparison
- Detects: `-enc`, `-encodedcommand`, `IEX`, `DownloadString`, `Invoke-Mimikatz`

#### File & Registry Operations
- **Suspicious File Operations**: Monitors executables/scripts in temp directories and public folders
- **Registry Modification Activity**: Tracks Run keys, Image File Execution Options, Winlogon persistence
- Uses Sysmon Event IDs 11 (File Create), 23 (File Delete), 12-14 (Registry)

#### Network Connections (Process-Level)
- **Sysmon Event ID 3**: Shows which process initiated each connection
- Filters infrastructure noise (DNS, DHCP, NTP, NetBIOS)
- Critical for identifying C2 communication and data exfiltration

#### Wazuh EDR Integration
- **Agent Health Monitoring**: Real-time status of Wazuh agents across all endpoints
- **File Integrity Monitoring**: Detects unauthorized changes to critical system files
- **Vulnerability Detection**: CVE-based assessment with severity classification (Critical/High/Medium/Low)
- **Compliance Scoring**: Assesses Sysmon + PowerShell logging maturity per endpoint

### What This Demonstrates
- **Defense-in-Depth Architecture**: Hybrid monitoring (Sysmon behavioral + Wazuh EDR)
- **Advanced Threat Detection**: Living-off-the-Land binary (LOLBin) abuse detection
- **PowerShell Attack Expertise**: Understanding of obfuscation, download cradles, fileless malware
- **Compliance & Vulnerability Management**: Risk-based patch prioritization
- **Regex & Field Extraction**: Complex command-line parsing and Base64 payload extraction

---

## 5. Network Traffic Analysis Dashboard

### Purpose
Comprehensive network-based threat detection dashboard providing real-time visibility into Suricata IDS/IPS alerts, protocol analysis, traffic patterns, and network conversations.

### Key Features
- **11 Panels**: 4 KPIs, 4 visualizations, 3 investigation tables
- **Auto-refresh**: Every 5 minutes
- **Time Range**: Last 24 hours (adjustable)
- **Data Sources**: Suricata IDS (via AWS VPC Traffic Mirroring)

### Technical Capabilities

#### IDS Alert Monitoring
- **Total Suricata Alerts**: Volume-based threat landscape assessment
- **Critical/High Severity Filtering**: Priority threat identification requiring immediate response
- **Unique Alerting IPs**: Attack distribution and scope analysis
- **63,022 ET Open Signatures**: Emerging Threats community ruleset for attack detection

#### Alert Analysis
- **Severity Distribution**: Visual breakdown (Critical/High/Medium/Low) showing threat composition
- **Timeline Visualization**: Identifies attack patterns, sustained campaigns, and temporal anomalies
- Enables differentiation between gradual reconnaissance vs. sudden exploitation

#### Threat Intelligence
- **Top Alerting Source IPs**: Ranks threat sources with signature diversity and timing context
- **Top Triggered Signatures**: Identifies most frequent attack types and techniques
- Distinguishes Suricata protocol analysis from ET attack signatures

#### Protocol & Traffic Analysis
- **Traffic by Protocol**: Distribution across TCP/UDP/ICMP for baseline establishment
- **Top Destination Ports**: Service identification revealing normal vs. abnormal port usage
- **Network Conversations**: Source→Destination mapping with connection frequency and data volume

#### AWS Cloud Integration
- **VPC Traffic Mirroring**: Cloud-native packet capture for IDS analysis
- **VXLAN Awareness**: Proper handling of AWS overlay networking (port 4789)
- Demonstrates modern cloud security architecture understanding

### What This Demonstrates
- **Network Security Monitoring**: IDS/IPS deployment and signature-based detection
- **Protocol Analysis Expertise**: TCP/UDP/ICMP traffic classification and anomaly detection
- **Cloud Security Skills**: AWS VPC Traffic Mirroring implementation
- **Signature Tuning**: False positive management and rule optimization
- **Network Forensics**: Connection pattern analysis and data flow investigation

---

## 🔧 Technology Stack

### Data Collection Layer
- **Sysmon**: Process creation, network connections, file operations, registry modifications
- **Windows Event Logs**: Authentication (4624/4625), privileges (4672), scheduled tasks (4698), services (7045)
- **Suricata IDS**: Network traffic analysis via AWS VPC Traffic Mirroring
- **Wazuh EDR**: File integrity monitoring, vulnerability scanning, agent health

### Analysis Platform
- **Splunk Enterprise**: Centralized SIEM for log aggregation, correlation, and visualization
- **Splunk Universal Forwarder**: Agent-based log collection from endpoints and sensors
- **SPL (Search Processing Language)**: Custom correlation searches and dashboard queries

### Cloud Infrastructure
- **AWS EC2**: Hosting for Splunk, Suricata, Wazuh servers, and Windows infrastructure
- **AWS VPC Traffic Mirroring**: Network packet capture for IDS analysis
- **AWS Security Groups**: Distributed firewall for network segmentation

---

## 📈 Metrics Summary

| Dashboard | Total Panels | Data Sources | Refresh Rate | Primary Use Case |
|-----------|-------------|--------------|--------------|------------------|
| Security Operations Overview | 13 | 3 | 5 min | Executive security posture |
| Threat Hunting | 13 | 3 | 10 min | Proactive threat discovery |
| Incident Response | 15 | 3 | 15 min | Active incident investigation |
| Endpoint Security | 18 | 3 | 5 min | Host-based threat detection |
| Network Traffic Analysis | 11 | 1 | 5 min | Network-layer threat detection |
| **TOTAL** | **70** | **Hybrid** | **Variable** | **Defense-in-Depth SOC** |

---

## 🎯 Key Skills Demonstrated

### Technical Proficiency
✅ **SPL Query Development**: 70+ custom Splunk queries with statistical aggregation, field normalization, and regex extraction  
✅ **Multi-Source Correlation**: Integration of Sysmon, Windows Events, Suricata, and Wazuh data  
✅ **Data Visualization**: Color-coded metrics, time-series charts, heat maps, and severity indicators  
✅ **Field Extraction**: Complex parsing of XML event data, command-line arguments, and encoded payloads  

### Security Knowledge
✅ **MITRE ATT&CK Framework**: Technique mapping, tactic categorization, and kill chain progression  
✅ **Threat Detection**: Behavioral analytics, statistical anomaly detection, signature-based IDS  
✅ **Incident Response**: Timeline reconstruction, evidence collection, containment workflows  
✅ **Vulnerability Management**: CVE-based risk assessment and patch prioritization  

### Operational Excellence
✅ **Detection Engineering**: Custom correlation rules for brute force, PowerShell, privilege escalation  
✅ **False Positive Management**: Behavioral scoring, whitelisting, and threshold tuning  
✅ **Collection Health Monitoring**: Validation that all telemetry sources are operational  
✅ **Compliance & Maturity**: Endpoint monitoring coverage assessment and gap identification  

### Cloud & Architecture
✅ **AWS Security**: VPC Traffic Mirroring, Security Groups, cloud-native IDS deployment  
✅ **Defense-in-Depth**: Layered monitoring (endpoint, network, identity, application)  
✅ **Scalable Architecture**: Centralized SIEM with distributed collection agents  

---

## 📸 Dashboard Screenshots

> **Note**: Screenshots for all 5 dashboards are available in the `/screenshots/` directory of this repository, organized by dashboard name.

---

## 🔗 Related Documentation

- [Main README](./README.md) - Project overview and architecture
- [DETECTION-RULES.md](./DETECTION-RULES.md) - Detailed documentation of all 6 detection rules
- [ACTIVE-DIRECTORY.md](./ACTIVE-DIRECTORY.md) - Domain structure and Group Policy Objects

---

## 💼 Interview Preparation

These dashboards are designed to demonstrate hands-on security operations expertise for SOC Analyst interviews. Each dashboard includes:

- **2-Minute Executive Summary**: High-level overview for initial interview discussions
- **5-Minute Technical Deep Dive**: Detailed walkthrough for senior-level technical interviews
- **Common Interview Q&A**: Prepared responses to typical questions about detection logic, tuning, and response workflows

For interview preparation materials and talking points, see the comprehensive documentation in the Google Docs linked in the main README.

---

**Last Updated**: December 2024  
**Author**: Majid Khan  
**Contact**: [LinkedIn](https://www.linkedin.com/in/iamajidkhan) | [GitHub](https://github.com/iamajidkhan)
