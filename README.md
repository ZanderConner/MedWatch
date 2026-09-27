# MedWatch

MedWatch is an IT management and security monitoring platform for Medical Internet of Things (MIoT) devices. It helps hospital IT and security teams discover clinical devices, understand the protocols they speak, and flag risky or unauthorized behavior without actively probing fragile medical equipment.

## Inspiration

Hospitals depend on connected devices like imaging scanners, lab analyzers, PACS servers, EHR systems, and clinical workstations. These systems often run on segmented networks, use specialized protocols like DICOM and HL7, and cannot always be scanned aggressively like normal enterprise laptops.

That creates a hard problem for hospital security teams: they need visibility into what is on the network, but the safest way to get that visibility is passive. MedWatch was built around that idea. Instead of touching the devices directly, it listens to network traffic, identifies clinical protocols, builds an asset inventory, and surfaces policy violations that a human operator can review.

## What It Does

MedWatch passively monitors simulated hospital device networks and turns raw traffic into a live security dashboard.

Key features include:

- Passive asset discovery for MIoT and clinical infrastructure devices
- DICOM and HL7 protocol detection and metadata extraction
- A live asset inventory with confirmed and pending devices
- Multi-sensor support across separate clinical subnets
- Traffic analytics for protocol mix, packet flow, and suspicious activity
- Correlation rules that flag risky behavior, such as unauthorized DICOM initiators, unknown HL7 senders, or embedded devices exposing remote admin ports
- A realistic demo range with CT/MRI modality simulators, hematology analyzers, Orthanc PACS, Mirth Connect, OpenEMR, and a red-team traffic generator

In the demo, MedWatch watches two clinical networks:

- An imaging subnet where CT and MRI simulators send DICOM studies to Orthanc
- A lab subnet where hematology analyzers exchange HL7 messages through Mirth

A separate red-team container sends deliberately suspicious DICOM and HL7 traffic so MedWatch can detect unauthorized clinical-protocol activity in real time.

## How We Built It

MedWatch is built as a full-stack security platform plus a Docker-based hospital cyber range.

The sensor agent is written in Rust and captures packets passively from network taps. It classifies traffic, tracks flows, extracts lightweight protocol metadata, fingerprints assets, and ships events to the backend API.

The backend is a Node.js service that stores events and discovered assets, exposes read APIs for the dashboard, and runs correlation rules that generate security alerts. The frontend is a Vite/React dashboard for operators to inspect assets, sensors, live traffic, analytics, and policy violations.

For the demo environment, we used Docker Compose to model a small hospital network:

- OpenEMR for the EHR
- Mirth Connect for HL7 integration
- Orthanc as the PACS
- CT and MRI DICOM modality simulators
- HL7 hematology analyzer simulators
- A radiology workstation that creates normal background traffic
- Two MedWatch monitoring agents, one per clinical subnet
- A red-team box that generates unauthorized DICOM and HL7 traffic

One important implementation detail is that Docker bridge networks behave like switched networks, not hubs. A monitoring container attached normally to a bridge cannot see other containers' unicast traffic. To make the demo realistic, each MedWatch sensor resolves the host bridge device for its target Docker network and captures there, similar to how a real deployment would use a SPAN port or network tap.

## Challenges We Ran Into

The biggest challenge was making the demo environment behave like a real hospital network instead of a toy simulation. Clinical protocols are noisy and specialized, and passive monitoring only works if the sensor is placed correctly.

We had to solve several problems:

- Capturing real inter-container traffic from Docker bridge networks
- Distinguishing DICOM and HL7 traffic from generic TCP payloads
- Preserving protocol identity across multi-packet flows
- Avoiding invasive scanning or active probing assumptions
- Keeping simulated clinical traffic realistic enough to demonstrate useful detection
- Separating normal device behavior from intentionally suspicious red-team traffic

We also had to balance hackathon scope with correctness. The correlation rules are intentionally simple, but the pipeline is structured like a real product: sensors collect, backend correlates, dashboard explains, and operators confirm what is known-good.

## Accomplishments

We are proud that MedWatch is more than a mock dashboard. It includes a working cyber range, passive packet capture, clinical protocol parsing, backend ingestion, security correlation, and a live operator interface.

The demo can show a full workflow:

1. Clinical devices begin talking on the network.
2. MedWatch sensors observe DICOM and HL7 traffic passively.
3. Assets appear in the inventory with identity hints and observed protocols.
4. A red-team host sends unauthorized clinical-protocol traffic.
5. MedWatch raises alerts for unrecognized DICOM and HL7 identities.
6. The operator reviews, confirms, edits, or removes assets from the dashboard.

That end-to-end loop is the core of what we wanted to prove.

## What We Learned

We learned that visibility in medical networks has to be designed around safety. Traditional enterprise scanning assumptions do not always fit environments with embedded clinical equipment, legacy software, and uptime-sensitive workflows.

We also learned how much network placement matters. Passive monitoring sounds simple, but in both real switched networks and Docker bridge networks, a sensor only sees useful traffic if it is connected to the right observation point.

On the implementation side, we learned how to parse just enough DICOM and HL7 metadata to identify devices and detect suspicious behavior without collecting sensitive patient data.

## What's Next

The next steps for MedWatch are:

- Replace demo hardcoded allowlists with configurable hospital asset policies
- Add richer device fingerprinting and confidence scores
- Support more medical and operational protocols
- Add alert triage workflows and integrations with ticketing or SIEM tools
- Build deployment profiles for real network taps, SPAN ports, and Kubernetes environments
- Improve historical analytics and incident timelines
- Add role-based access control for hospital IT and security teams

Long term, MedWatch could become a safety-first security layer for clinical networks: passive by default, protocol-aware, and built for the realities of hospital operations.

## Built With

- Rust
- Node.js
- React
- Vite
- SQLite
- Docker Compose
- DICOM
- HL7v2 / MLLP
- Orthanc
- Mirth Connect
- OpenEMR

## Short Description

MedWatch is a passive IT management and security platform for Medical IoT devices. It discovers clinical assets, analyzes DICOM and HL7 traffic, and flags unauthorized behavior across simulated hospital networks.

## Tagline

Passive security visibility for Medical IoT networks.

## Prior Research

Medical device cybersecurity is a complex, multifaceted domain where the balance between clinical utility, patient safety, and information security presents significant challenges. Literature across multiple studies emphasizes that medical systems often operate within highly vulnerable environments due to a combination of architectural limitations, systemic software flaws, and supply chain dependencies.

Key Contributing Factors & Systemic Issues
**Legacy Infrastructure and Patching:** Many healthcare systems rely on legacy operating systems and software that are five or more years old. Timely patching and updates are complex because updates require manufacturer input to ensure patient care is not disrupted.

**Design Paradigm (Safety vs. Security):** Medical devices have traditionally been designed with a primary focus on physical safety and preventing operational malfunctions, leading developers to falsely assume that network communications are inherently trusted.

**Resource Constraints:** Due to the limited power and computational resources of many medical devices, applying standard encryption can degrade device performance and reduce usable battery life. Furthermore, financial and resource limitations often prevent organizations from properly supporting complex IT security environments.

**Supply Chain Vulnerabilities:** Attackers frequently bypass hardened hospital networks by targeting third-party vendors with weaker security defenses, utilizing a "hub and spoke" strategy to pivot across interconnected healthcare providers.

**Extended Exposure Windows:** Capital-intensive equipment (such as MRIs) remains in service much longer than traditional IT software. Additionally, a significant average time gap (approximately 3.2 years) often exists between a hospital purchasing a device and a vulnerability being publicly announced, leaving a massive window for zero-day exploits.

Core Vulnerabilities & Impacts

**CIA Triad Compromises:**

**Confidentiality:** Poor access control measures lead to unauthorized data exposure impacting HIPAA compliance and risking reputational or financial consequences.
Integrity: Poor configurations, corrupted data, and unauthorized manipulation of device settings (such as altering computed tomography / radiator doses or drug dosages on insulin pumps) directly threaten patient safety and clinical decision-making.

**Availability:** Limited or lost access to data and devices can prevent clinicians from receiving critical alerts or vital information in a timely manner.
  
**Widespread Software Weaknesses (CWEs):** Common technical flaws identified across studies include hard-coded credentials (CWE-798), lack of or improper authentication (CVE-2021-33882, CWE-287), information exposure (CWE-200), cleartext transmission of sensitive data (CWE-319), and improper input validation or privilege management.

**Real-World Attack Vectors & Targeted Devices:** Documented vulnerabilities affect diverse equipment—including patient monitors, diagnostic imaging systems (MRIs, CTs), infusion and insulin pumps, and implantable cardiac devices (pacemakers, defibrillators). Common vectors involve unencrypted protocols (such as Bluetooth Low Energy), built-in hardcoded backdoors, insecure web interfaces, and ransomware-induced device failures.

**References**
1. Bracciale, L., Loreti, P., & Bianchi, G. (2023). Cybersecurity vulnerability analysis of medical devices purchased by national health services. Scientific Reports, 13, 19509.
2. Mathew, A., & Alex, H. (2022). Detect & protect-medical device cybersecurity. Current Overview of Science and Technology Research, 1, 60–68.
3. Williams, P. A., & Woodward, A. J. (2015). Cybersecurity vulnerabilities in medical devices: a complex environment and multifaceted problem. Medical Devices: Evidence and Research, 8, 305–316.
