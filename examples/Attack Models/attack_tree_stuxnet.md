graph BT
    root["[G01] CPS Disruption: Compromise of Nuclear Power Plant Cyber-Physical Systems Leading to Operational Disruption or Safety Hazard"]
    spoofing_path["[H01] Unauthorized Control Actions via Spoofed Operator Credentials"]
    spoofing_path --> root
    hmi_spoof_1["[A01] Siemens SIMATIC HMI (Purdue Level 3)"]
    hmi_spoof_1 --> spoofing_path
    hmi_vuln_1["[V01] Weak Authentication Mechanism (CVE-2017-9618)"]
    hmi_vuln_1 --> hmi_spoof_1
    hmi_exploit_1["[H02] Unauthorized HMI Access via Credential Spoofing"]
    hmi_exploit_1 --> hmi_vuln_1
    plc_command_injection_1["[A02] PLC Command Injection (Modbus/TCP or S7 Protocol)"]
    plc_command_injection_1 --> hmi_exploit_1
    plc_unsafe_operation_1["[H03] Unsafe Control Actions (e.g., Valve Manipulation, Rod Positioning)"]
    plc_unsafe_operation_1 --> plc_command_injection_1
    attacker["[U01] Attacker"]
    attacker --> plc_unsafe_operation_1
    tampering_path["[H04] Altered Control Logic via Compromised Engineering Workstation"]
    tampering_path --> root
    ews_tamper_1["[A03] Schneider Electric EcoStruxure Engineering Workstation (Purdue Level 3)"]
    ews_tamper_1 --> tampering_path
    ews_vuln_1["[V02] Supply Chain Compromise (CVE-2020-15782)"]
    ews_vuln_1 --> ews_tamper_1
    logic_tamper_1["[H05] Malicious Control Logic Injection (e.g., Altered Setpoints, Disabled Safeguards)"]
    logic_tamper_1 --> ews_vuln_1
    plc_deploy_1["[A04] PLC Firmware/Logic Deployment (S7 or CIP Protocol)"]
    plc_deploy_1 --> logic_tamper_1
    unsafe_process_conditions_1["[H06] Unsafe Process Conditions (e.g., Overpressure, Coolant Loss)"]
    unsafe_process_conditions_1 --> plc_deploy_1
    attacker --> unsafe_process_conditions_1
    repudiation_path["[H07] Loss of Accountability via Disabled Logging"]
    repudiation_path --> root
    historian_repudiation_1["[A05] OSIsoft PI Historian Server (Purdue Level 3.5)"]
    historian_repudiation_1 --> repudiation_path
    historian_vuln_1["[V03] Logging Mechanism Disablement (CVE-2018-10612)"]
    historian_vuln_1 --> historian_repudiation_1
    log_tamper_1["[H08] Unauthorized Deletion/Modification of Process Logs"]
    log_tamper_1 --> historian_vuln_1
    forensic_evasion_1["[H09] Hindrance of Incident Response and Attribution"]
    forensic_evasion_1 --> log_tamper_1
    attacker --> forensic_evasion_1
    info_disclosure_path["[H10] Exposure of Sensitive Operational Data"]
    info_disclosure_path --> root
    protocol_disclosure_1["[A06] Modbus/TCP Communication Link (Purdue Level 3-2)"]
    protocol_disclosure_1 --> info_disclosure_path
    protocol_vuln_1["[V04] Unencrypted Protocol Traffic (CVE-2019-10958)"]
    protocol_vuln_1 --> protocol_disclosure_1
    traffic_intercept_1["[H11] Eavesdropping on HMI-PLC Traffic (e.g., Setpoints, Alarm States)"]
    traffic_intercept_1 --> protocol_vuln_1
    data_exfil_1["[A07] Operational Data Exfiltration to C2 Server"]
    data_exfil_1 --> traffic_intercept_1
    process_insight_abuse_1["[H12] Adversary Gains Insight for Further Exploitation (e.g., Timing Attacks, Sabotage Planning)"]
    process_insight_abuse_1 --> data_exfil_1
    attacker --> process_insight_abuse_1
    dos_path["[H13] Disruption of Critical Communication Pathways"]
    dos_path --> root
    network_dos_1["[A08] Cisco Industrial Switch (Purdue Level 2-3 Boundary)"]
    network_dos_1 --> dos_path
    network_vuln_1["[V05] Network Flooding Vulnerability (CVE-2016-5696)"]
    network_vuln_1 --> network_dos_1
    traffic_flood_1["[H14] Modbus/TCP or DNP3 Traffic Flooding"]
    traffic_flood_1 --> network_vuln_1
    comm_loss_1["[H15] Loss of HMI-PLC Communication (e.g., Valve Status, Sensor Feedback)"]
    comm_loss_1 --> traffic_flood_1
    unsafe_state_transition_1["[H16] Unsafe Process State Transition Due to Lack of Feedback"]
    unsafe_state_transition_1 --> comm_loss_1
    attacker --> unsafe_state_transition_1
    priv_escalation_path["[H17] Unauthorized Administrative Access to Engineering Workstation"]
    priv_escalation_path --> root
    ews_priv_esc_1["[A09] Siemens SIMATIC PCS 7 Engineering Workstation (Purdue Level 3)"]
    ews_priv_esc_1 --> priv_escalation_path
    ews_vuln_2["[V06] Privilege Escalation Vulnerability (CVE-2021-22893)"]
    ews_vuln_2 --> ews_priv_esc_1
    admin_access_1["[H18] Administrative Access to Control Logic Repository"]
    admin_access_1 --> ews_vuln_2
    malicious_deployment_1["[A10] Deployment of Malicious Control Logic to PLCs (S7 Protocol)"]
    malicious_deployment_1 --> admin_access_1
    safety_bypass_1["[H19] Bypass of Safety Instrumented Systems (SIS) or Interlocks"]
    safety_bypass_1 --> malicious_deployment_1
    attacker --> safety_bypass_1
    lateral_movement_path["[H20] Compromise of Critical Systems via Lateral Movement"]
    lateral_movement_path --> root
    printer_pivot_1["[A11] Network-Attached Printer (Purdue Level 3.5)"]
    printer_pivot_1 --> lateral_movement_path
    printer_vuln_1["[V07] Default Credentials or Unpatched Firmware"]
    printer_vuln_1 --> printer_pivot_1
    pivot_to_hmi_1["[A12] Pivot to HMI via Weak Network Segmentation"]
    pivot_to_hmi_1 --> printer_vuln_1
    hmi_lateral_1["[A13] Siemens WinCC HMI (Purdue Level 3)"]
    hmi_lateral_1 --> pivot_to_hmi_1
    hmi_exploit_2["[V08] Unauthenticated Command Execution (e.g., via OPC UA)"]
    hmi_exploit_2 --> hmi_lateral_1
    plc_unsafe_command_1["[H21] Unsafe PLC Commands (e.g., Emergency Shutdown Disablement)"]
    plc_unsafe_command_1 --> hmi_exploit_2
    attacker --> plc_unsafe_command_1
    supply_chain_path["[H22] Compromised Firmware or Remote Support Tools"]
    supply_chain_path --> root
    vendor_update_1["[A14] Vendor-Signed Firmware Update (Purdue Level 2-3)"]
    vendor_update_1 --> supply_chain_path
    firmware_vuln_1["[V09] Backdoored Firmware (e.g., via Compromised Vendor Portal)"]
    firmware_vuln_1 --> vendor_update_1
    plc_backdoor_1["[A15] Backdoor in PLC Logic (e.g., Hidden Function Blocks)"]
    plc_backdoor_1 --> firmware_vuln_1
    process_sabotage_1["[H23] Delayed or Conditional Sabotage (e.g., Time-Based Attack)"]
    process_sabotage_1 --> plc_backdoor_1
    attacker --> process_sabotage_1
    remote_support_1["[A16] Vendor Remote Support Tool (e.g., TeamViewer, Siemens TIA Portal Remote)"]
    remote_support_1 --> supply_chain_path
    support_vuln_1["[V10] Excessive Privileges or Weak Authentication"]
    support_vuln_1 --> remote_support_1
    support_session_hijack_1["[H24] Hijacked Remote Support Session"]
    support_session_hijack_1 --> support_vuln_1
    plc_reprogram_1["[A17] Direct Reprogramming of PLCs via Vendor Tool"]
    plc_reprogram_1 --> support_session_hijack_1
    unsafe_control_1["[H25] Unsafe Control Actions (e.g., Coolant Pump Disablement)"]
    unsafe_control_1 --> plc_reprogram_1
    attacker --> unsafe_control_1
    data_integrity_path["[H26] Tampering with Process Data or Setpoints"]
    data_integrity_path --> root
    historian_integrity_1["[A18] OSIsoft PI Historian Database (Purdue Level 3.5)"]
    historian_integrity_1 --> data_integrity_path
    historian_vuln_2["[V11] SQL Injection or Direct Database Access"]
    historian_vuln_2 --> historian_integrity_1
    data_manipulation_1["[H27] Alteration of Stored Process Data (e.g., Temperature, Pressure Records)"]
    data_manipulation_1 --> historian_vuln_2
    compliance_violation_1["[H28] Falsified Compliance Reports or Masked Anomalies"]
    compliance_violation_1 --> data_manipulation_1
    attacker --> compliance_violation_1
    setpoint_injection_1["[A19] HMI Setpoint Injection Interface (Purdue Level 3)"]
    setpoint_injection_1 --> data_integrity_path
    hmi_vuln_3["[V12] Lack of Input Validation in Setpoint Fields"]
    hmi_vuln_3 --> setpoint_injection_1
    setpoint_abuse_1["[H29] Unauthorized Modification of Control Loop Setpoints (e.g., Reactor Power, Coolant Flow)"]
    setpoint_abuse_1 --> hmi_vuln_3
    plc_unsafe_setpoint_1["[A20] PLC Execution of Unsafe Setpoints (e.g., Overpower Condition)"]
    plc_unsafe_setpoint_1 --> setpoint_abuse_1
    physical_damage_1["[H30] Physical Damage to Reactor Components or Safety Systems"]
    physical_damage_1 --> plc_unsafe_setpoint_1
    attacker --> physical_damage_1
    physical_tampering_path["[H31] Physical Tampering with Field Devices"]
    physical_tampering_path --> root
    sensor_tamper_1["[A21] Radiation Monitor Sensor (Purdue Level 0-1)"]
    sensor_tamper_1 --> physical_tampering_path
    sensor_vuln_1["[V13] Lack of Physical Security or Tamper-Evident Seals"]
    sensor_vuln_1 --> sensor_tamper_1
    sensor_spoof_1["[H32] Spoofed Sensor Readings (e.g., False Low-Radiation Signals)"]
    sensor_spoof_1 --> sensor_vuln_1
    plc_false_feedback_1["[A22] PLC Receives False Process Feedback"]
    plc_false_feedback_1 --> sensor_spoof_1
    unsafe_control_decision_1["[H33] Unsafe Automated Control Decisions (e.g., Disabled Safety Actions)"]
    unsafe_control_decision_1 --> plc_false_feedback_1
    attacker --> unsafe_control_decision_1
    actuator_sabotage_1["[A23] Coolant Valve Actuator (Purdue Level 0-1)"]
    actuator_sabotage_1 --> physical_tampering_path
    actuator_vuln_1["[V14] Unsecured Actuator Control Interface (e.g., Modbus RTU)"]
    actuator_vuln_1 --> actuator_sabotage_1
    actuator_jam_1["[H34] Actuator Jamming or Unauthorized Command Injection"]
    actuator_jam_1 --> actuator_vuln_1
    coolant_loss_1["[H35] Loss of Coolant Flow or Overpressure Scenario"]
    coolant_loss_1 --> actuator_jam_1
    attacker --> coolant_loss_1