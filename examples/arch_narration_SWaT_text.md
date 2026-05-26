**Attacker or Attack-Capable Entities**
- **Researchers**: Explicitly mentioned as entities with "complete access to the control logic within the PLCs and HMIs" for code development and upload, implying privileged but potentially misuse-capable access.
- **Operators/Administrators**: Implied by the SCADA’s ability to "override the pre-existing PLC programming" and take "manual control," suggesting human-in-the-loop capabilities with high-level access.
- **External Adversaries**: Implied by the presence of "wireless communications" via Wireless Access Points (WAPs), which introduce potential entry points for unauthorized actors.
- **Interconnected Testbeds**: The "interconnection among the testbeds" suggests lateral movement risks from compromised adjacent systems or shared networks.

---

**Key Components**
- **OT Hardware**:
  - **Allen-Bradley Programmable Logic Controllers (PLCs)**: Core control devices executing process logic.
  - **Schneider Remote Input/Output (RIO) Units**: Field-level devices interfacing sensors/actuators with PLCs.
- **IT Hardware/Software**:
  - **Human Machine Interfaces (HMIs)**: Operator interfaces for monitoring/control, co-located with OT.
  - **SCADA Workstation**: Supervisory system for process monitoring, manual override, and control logic management.
  - **Historian**: Dedicated system for recording and storing process data for analysis.
- **Network Infrastructure**:
  - **Layered Communications Network**: Structured per the Purdue Model, segmenting IT/OT traffic.
  - **Wireless Access Points (WAPs)**: Enabling wireless connectivity for research access and potential experimental code deployment.
  - **Wired and Wireless Communications**: Mixed-media network links between components.
- **Interconnections**: Explicit links between testbeds, implying shared or bridged network segments.

---

**Trust Boundaries and Purdue Zones**
- **Purdue Model Compliance**: The architecture explicitly adopts the Purdue Model for ICS, implying the following zones (though not visually detailed, inferred from description):
  - **Level 0 (Physical Process)**: Field devices (sensors/actuators) interfaced via RIO units.
  - **Level 1 (Basic Control)**: PLCs and RIO units executing real-time control logic.
  - **Level 2 (Supervisory Control)**: SCADA workstation and HMIs for monitoring/override.
  - **Level 3 (Site Operations)**: Historian for data storage/analysis; potential IT/OT convergence.
  - **Level 4 (Enterprise)**: Not explicitly mentioned but implied as a possible extension for data analytics or remote access.
- **Trust Boundaries**:
  - **IT/OT Segmentation**: Layered network separates IT (SCADA/Historian) and OT (PLCs/RIOs) components.
  - **Wireless Boundary**: WAPs introduce a distinct trust boundary for wireless access, bridging to wired segments.
  - **Testbed Interconnection**: Shared boundaries between interconnected testbeds, enabling cross-testbed lateral movement.

---

**Data Flows & Interactions**
- **PLC ↔ RIO Units**:
  - **Protocol**: EtherNet/IP (ENIP) for real-time I/O data exchange and control commands.
  - **Data Types**: Process variables (e.g., sensor readings, actuator states), control logic updates.
- **PLC ↔ SCADA/HMI**:
  - **Protocol**: ENIP (or proprietary SCADA protocols) for supervisory monitoring and manual override commands.
  - **Data Types**: Process telemetry, alarms, control setpoints, logic overrides.
- **SCADA ↔ Historian**:
  - **Protocol**: Likely SQL, OPC UA, or proprietary historian protocols.
  - **Data Types**: Time-series process data, event logs, historical trends.
- **Researcher ↔ PLC/HMI**:
  - **Protocol**: Likely ENIP or vendor-specific (e.g., Allen-Bradley’s Studio 5000) for code upload/download.
  - **Data Types**: Control logic programs, firmware, configuration files.
- **Wireless Links (via WAPs)**:
  - **Protocol**: Wi-Fi (IEEE 802.11) or proprietary wireless industrial protocols.
  - **Data Types**: Remote access traffic, code deployment, monitoring data.
- **Testbed Interconnections**:
  - **Protocol**: Not specified; potentially ENIP, Modbus/TCP, or routed IP traffic.
  - **Data Types**: Shared process data, control synchronization, or experimental traffic.

---

**Technologies and Protocols**
- **Industrial Protocols**:
  - **EtherNet/IP (ENIP)**: Primary protocol for PLC-RIO and PLC-SCADA communication.
- **Wireless Standards**:
  - **IEEE 802.11 (Wi-Fi)**: Used by WAPs for wireless access.
- **SCADA/Historian Protocols**:
  - **OPC UA** (implied but not confirmed): Possible for SCADA-Historian data exchange.
  - **SQL/NoSQL**: Likely for Historian data storage/retrieval.
- **Programming/Development Tools**:
  - **Allen-Bradley Studio 5000** (or equivalent): For PLC logic development/upload.
  - **Schneider EcoStruxure** (or equivalent): For RIO configuration.
- **Network Technologies**:
  - **Layered Networking**: Purdue Model-based segmentation (firewalls, VLANs, or physical separation implied).
  - **Mixed Wired/Wireless**: Ethernet (for ENIP) and Wi-Fi (for research access).

---

**Assets and Functions**
- **Cyber-Physical Assets**:
  - **PLCs**: Execute control logic for physical processes (e.g., water treatment stages).
  - **RIO Units**: Interface field devices (sensors/actuators) with PLCs.
  - **HMIs**: Provide operator visualization and manual control interfaces.
  - **SCADA Workstation**: Supervises process, logs data, and enables manual overrides.
  - **Historian**: Stores process data for analysis and forensics.
- **Critical Functions**:
  - **Real-Time Control**: PLCs managing physical processes (e.g., valve actuation, chemical dosing).
  - **Supervisory Override**: SCADA’s ability to bypass PLC logic for manual control.
  - **Data Logging**: Historian’s role in recording process variables for auditing.
  - **Code Deployment**: Researcher access to upload/modify PLC/HMI logic.
  - **Wireless Access**: WAPs enabling remote connectivity for experimentation.
- **Interconnected Testbeds**: Shared assets/functions across linked testbeds, enabling cross-system interactions.

---

**Attack Entry Points**
- **Wireless Access Points (WAPs)**:
  - Unauthorized access via Wi-Fi (e.g., rogue device connection, MITM, or credential exploitation).
- **Researcher Access Pathways**:
  - Code upload interfaces in PLCs/HMIs (e.g., malicious logic injection, firmware tampering).
- **SCADA/HMI Interfaces**:
  - Manual override capabilities (e.g., unauthorized control actions, logic bypass).
- **Historian System**:
  - Data tampering or exfiltration via Historian access (e.g., SQL injection, unauthorized queries).
- **EtherNet/IP Network**:
  - Protocol-level attacks (e.g., ENIP packet injection, spoofing, or replay attacks).
- **Testbed Interconnections**:
  - Lateral movement from compromised adjacent testbeds (e.g., pivoting via shared network segments).
- **Physical Access**:
  - Implied by "complete access to control logic" for researchers (e.g., direct console access, USB-based attacks).
- **Human Operators**:
  - Insider threats via HMI/SCADA privileges (e.g., malicious overrides, misconfiguration).