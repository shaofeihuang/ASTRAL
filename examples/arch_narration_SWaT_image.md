**Attacker or Attack-Capable Entities**
- **Implied Adversaries**: Entities with physical or logical access to the network, including:
  - **Researchers/Operators**: Capable of uploading custom code to PLCs/HMIs via wireless or wired access, potentially introducing malicious logic.
  - **Unauthorized Wireless Actors**: Attackers exploiting Wireless Access Points (WAPs) to intercept or inject traffic.
  - **Insider Threats**: Legitimate users (e.g., SCADA operators) with override capabilities who may abuse manual control privileges.
  - **Network-Based Attackers**: Entities targeting exposed communication links (EtherNet/IP, wireless segments) or vulnerable IT/OT interfaces.

**Key Components**
- **OT Hardware**:
  - **Allen-Bradley PLCs**: Distributed controllers executing SWaT process logic, communicating via EtherNet/IP.
  - **Schneider Remote I/O (RIO) Units**: Field-level devices interfacing sensors/actuators with PLCs.
- **IT Hardware/Software**:
  - **SCADA Workstation**: Supervisory system with monitoring, manual override, and control capabilities.
  - **HMIs**: Operator interfaces for process visualization and interaction with PLCs/RIOs.
  - **Historian**: Database storing process data for analysis, integrated with SCADA.
- **Network Infrastructure**:
  - **Wireless Access Points (WAPs)**: Enabling wireless communication for research access and potential attack vectors.
  - **Layered Network**: Segments aligned with Purdue Model zones (detailed below).
- **Communication Links**:
  - **Wired**: EtherNet/IP backbone connecting PLCs, RIOs, SCADA, and Historian.
  - **Wireless**: Links between WAPs and OT/IT components (e.g., HMIs, PLCs).

**Trust Boundaries and Purdue Zones**
- **Purdue Model Layers** (implied by description):
  - **Level 0 (Physical Process)**: Field devices (sensors/actuators) connected via RIOs.
  - **Level 1 (Basic Control)**: PLCs and RIOs executing control logic.
  - **Level 2 (Supervisory Control)**: SCADA workstation and HMIs for monitoring/override.
  - **Level 3 (Site Operations)**: Historian for data storage/analysis; potential IT/OT gateway.
  - **Level 4 (Enterprise)**: Not explicitly described but implied as a higher-level boundary for external connectivity (e.g., research access).
- **Trust Boundaries**:
  - **IT/OT Convergence**: SCADA and Historian bridge OT (PLCs/RIOs) and IT domains.
  - **Wireless Segments**: WAPs introduce a boundary between wired OT networks and wireless-accessible components.
  - **Manual Override**: SCADA’s ability to bypass PLC logic creates a trust boundary between automated and human-driven control.

**Data Flows & Interactions**
- **SCADA ↔ PLCs/RIOs**:
  - **Protocol**: EtherNet/IP.
  - **Data Types**: Process telemetry (sensor readings), control commands (actuator signals), and override instructions.
  - **Direction**: Bidirectional (monitoring upstream, commands downstream).
- **SCADA ↔ Historian**:
  - **Protocol**: Likely IT-standard (e.g., OPC UA, SQL), not specified.
  - **Data Types**: Process data logs, historical trends, and alerts.
  - **Direction**: Primarily SCADA → Historian (logging).
- **HMIs ↔ PLCs/SCADA**:
  - **Protocol**: EtherNet/IP or proprietary HMI protocols.
  - **Data Types**: Visualization data (real-time process states), operator inputs.
- **Wireless Links (WAPs)**:
  - **Entities**: Researchers/attackers uploading code to PLCs/HMIs; potential rogue device connections.
  - **Data Types**: Control logic updates, configuration changes, or malicious payloads.
- **Inter-Testbed Connections**:
  - **Implied Data Flows**: Shared process data or control signals between SWaT and other testbeds (protocol unspecified).

**Technologies and Protocols**
- **OT Protocols**:
  - **EtherNet/IP**: Primary protocol for PLC-RIO-SCADA communication (CIP-based, TCP/IP stack).
- **Wireless Technologies**:
  - **WAPs**: Standard Wi-Fi (IEEE 802.11) for researcher/operator access; security protocols (e.g., WPA2/3) not specified.
- **IT Protocols**:
  - **Historian Integration**: Likely database protocols (e.g., ODBC, SQL) or industrial standards (OPC UA).
  - **HMI Protocols**: Proprietary or standard (e.g., Modbus TCP, if secondary to EtherNet/IP).
- **Standards**:
  - **Purdue Model**: Structural framework for ICS segmentation.
  - **IEC 62443**: Implied by reference to Purdue Model and OT/IT convergence (though not explicitly stated).

**Assets and Functions**
- **Cyber-Physical Assets**:
  - **PLCs**: Execute ladder logic for water treatment processes (e.g., valve control, pump sequencing).
  - **RIOs**: Distributed I/O for sensor/actuator interfacing (e.g., flow meters, chemical injectors).
  - **SCADA**: Supervisory monitoring, alarming, and manual override of PLC logic.
  - **HMIs**: Operator dashboards for process visualization and direct control inputs.
  - **Historian**: Time-series database for forensic analysis and process optimization.
- **Critical Functions**:
  - **Real-Time Control**: PLC-driven automation of physical processes (e.g., water flow, chemical dosing).
  - **Manual Override**: SCADA’s ability to supersede PLC logic, introducing a single point of failure.
  - **Data Logging**: Historian’s role in audit trails and post-incident analysis.
  - **Wireless Access**: Researcher uploads to PLCs/HMIs (potential for unauthorized code deployment).

**Attack Entry Points**
- **Wireless Access Points (WAPs)**:
  - Unauthorized connection to upload malicious logic or eavesdrop on traffic.
- **SCADA Workstation**:
  - Compromise via IT vectors (e.g., phishing, exploit kits) to manipulate process control or exfiltrate data.
- **HMIs**:
  - Exposed interfaces for operator interaction; vulnerable to HMI-specific exploits (e.g., buffer overflows).
- **EtherNet/IP Network**:
  - Protocol vulnerabilities (e.g., CIP stack exploits, MITM attacks on unencrypted traffic).
- **Manual Override Mechanism**:
  - Abuse of SCADA’s override capability to issue unsafe commands (e.g., valve shutdowns).
- **Historian Database**:
  - SQL injection or data tampering to corrupt process logs.
- **Inter-Testbed Connections**:
  - Lateral movement from compromised adjacent testbeds.
- **Physical Access**:
  - Direct tampering with PLCs/RIOs or wired network taps.