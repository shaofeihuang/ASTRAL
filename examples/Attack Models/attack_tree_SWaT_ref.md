graph BT
    root["[G00] Disrupt or Stop Water Treatment Plant Cyber-Physical Operations"]
    spoof_operator_commands["[G01] Spoof Legitimate Operator Commands to Disrupt Control Logic"]
    spoof_operator_commands --> root
    scada_auth_weakness["[A01] SCADA System (Authentication Mechanisms)"]
    scada_auth_weakness --> spoof_operator_commands
    weak_auth_protocols["[V01] Weak or Default Authentication Protocols (e.g., Modbus, DNP3)"]
    weak_auth_protocols --> scada_auth_weakness
    unencrypted_comms["[V02] Unencrypted Communication Channels"]
    unencrypted_comms --> weak_auth_protocols
    attacker["[U01] Attacker"]
    attacker --> unencrypted_comms
    default_credentials["[V03] Default or Hardcoded Credentials in PLC/HMI"]
    default_credentials --> weak_auth_protocols
    attacker["[U01] Attacker"]
    attacker --> default_credentials
    hmi_credential_spoof["[A02] HMI (Operator Credential Handling)"]
    hmi_credential_spoof --> spoof_operator_commands
    session_hijacking["[V04] Session Hijacking via Unattended HMI Consoles"]
    session_hijacking --> hmi_credential_spoof
    attacker["[U01] Attacker"]
    attacker --> session_hijacking
    credential_theft["[V05] Theft of Operator Credentials via Phishing or Keylogging"]
    credential_theft --> hmi_credential_spoof
    attacker["[U01] Attacker"]
    attacker --> credential_theft
    tamper_control_logic["[G02] Tamper with Control Logic or Process Data to Cause Physical Disruption"]
    tamper_control_logic --> root
    plc_unauthorized_access["[A03] PLC/RTU (Control Logic Execution)"]
    plc_unauthorized_access --> tamper_control_logic
    unsecured_engineering_access["[V06] Unsecured Engineering Workstation Access to PLC"]
    unsecured_engineering_access --> plc_unauthorized_access
    firmware_backdoor["[V07] Malicious Firmware or Backdoors in PLC (Supply Chain Risk)"]
    firmware_backdoor --> unsecured_engineering_access
    attacker["[U01] Attacker"]
    attacker --> firmware_backdoor
    unpatched_vulnerabilities["[V08] Unpatched Vulnerabilities in PLC (e.g., CVE-2019-10976)"]
    unpatched_vulnerabilities --> unsecured_engineering_access
    attacker["[U01] Attacker"]
    attacker --> unpatched_vulnerabilities
    mitm_protocol_weakness["[V09] Man-in-the-Middle (MITM) Exploiting Unencrypted Industrial Protocols"]
    mitm_protocol_weakness --> plc_unauthorized_access
    modbus_dnp3_spoof["[H01] Spoofed Modbus/DNP3 Commands to Actuators"]
    modbus_dnp3_spoof --> mitm_protocol_weakness
    valve_malfunction["[H02] Unauthorized Valve Actuation Leading to Overflow/Leakage"]
    valve_malfunction --> modbus_dnp3_spoof
    attacker["[U01] Attacker"]
    attacker --> valve_malfunction
    sensor_data_falsification["[A04] Sensors (Process Data Integrity)"]
    sensor_data_falsification --> tamper_control_logic
    sensor_spoofing["[V10] Sensor Spoofing via Physical or Network-Based Tampering"]
    sensor_spoofing --> sensor_data_falsification
    false_telemetry["[H03] False Telemetry Triggering Unsafe Control Actions"]
    false_telemetry --> sensor_spoofing
    overchlorination["[H04] Overchlorination or Chemical Imbalance"]
    overchlorination --> false_telemetry
    attacker["[U01] Attacker"]
    attacker --> overchlorination
    repudiation_attacks["[G03] Perform Unauthorized Actions with Impunity (Repudiation)"]
    repudiation_attacks --> root
    scada_log_tampering["[A05] SCADA System (Audit Logging)"]
    scada_log_tampering --> repudiation_attacks
    insufficient_logging["[V11] Insufficient or Disabled Logging Mechanisms"]
    insufficient_logging --> scada_log_tampering
    log_deletion["[V12] Deletion or Alteration of Logs Post-Attack"]
    log_deletion --> insufficient_logging
    attacker["[U01] Attacker"]
    attacker --> log_deletion
    hmi_action_obfuscation["[A06] HMI (Audit Trail Integrity)"]
    hmi_action_obfuscation --> repudiation_attacks
    weak_audit_trails["[V13] Weak or Nonexistent Audit Trails for Operator Actions"]
    weak_audit_trails --> hmi_action_obfuscation
    unattributed_commands["[H05] Unattributed Control Commands Leading to Process Disruption"]
    unattributed_commands --> weak_audit_trails
    attacker["[U01] Attacker"]
    attacker --> unattributed_commands
    information_disclosure["[G04] Exfiltrate Sensitive Operational Data for Further Attacks"]
    information_disclosure --> root
    scada_data_exfil["[A07] SCADA System (Data Confidentiality)"]
    scada_data_exfil --> information_disclosure
    unpatched_scada_vuln["[V14] Exploitable Vulnerabilities in SCADA (e.g., CVE-2020-14495)"]
    unpatched_scada_vuln --> scada_data_exfil
    data_theft["[H06] Theft of Process Parameters (e.g., Chemical Dosages, Flow Rates)"]
    data_theft --> unpatched_scada_vuln
    attacker["[U01] Attacker"]
    attacker --> data_theft
    hmi_plc_comms_intercept["[A08] HMI-PLC Communication Channel"]
    hmi_plc_comms_intercept --> information_disclosure
    unencrypted_hmi_plc["[V15] Unencrypted Communication Between HMI and PLC"]
    unencrypted_hmi_plc --> hmi_plc_comms_intercept
    credential_capture["[H07] Capture of Operator Credentials or Control Logic Details"]
    credential_capture --> unencrypted_hmi_plc
    attacker["[U01] Attacker"]
    attacker --> credential_capture
    denial_of_service["[G05] Disrupt System Availability via Denial-of-Service (DoS)"]
    denial_of_service --> root
    scada_dos["[A09] SCADA System (Availability)"]
    scada_dos --> denial_of_service
    network_flooding["[V16] Network Flooding or Resource Exhaustion Attacks"]
    network_flooding --> scada_dos
    scada_unresponsive["[H08] SCADA System Becomes Unresponsive"]
    scada_unresponsive --> network_flooding
    loss_of_monitoring["[H09] Loss of Monitoring and Control Capabilities"]
    loss_of_monitoring --> scada_unresponsive
    attacker["[U01] Attacker"]
    attacker --> loss_of_monitoring
    plc_fault_state["[A10] PLC (Fault Tolerance)"]
    plc_fault_state --> denial_of_service
    plc_exploit["[V17] Exploitation of PLC Vulnerabilities (e.g., CVE-2019-10976)"]
    plc_exploit --> plc_fault_state
    plc_crash["[H10] PLC Enters Fault State or Reboots Repeatedly"]
    plc_crash --> plc_exploit
    process_halt["[H11] Halt in Water Treatment Process"]
    process_halt --> plc_crash
    attacker["[U01] Attacker"]
    attacker --> process_halt
    privilege_escalation["[G06] Elevate Privileges to Gain Unauthorized Control"]
    privilege_escalation --> root
    hmi_priv_esc["[A11] HMI (Privilege Management)"]
    hmi_priv_esc --> privilege_escalation
    hmi_vuln_exploit["[V18] Exploitable Vulnerabilities in HMI (e.g., CVE-2021-22893)"]
    hmi_vuln_exploit --> hmi_priv_esc
    admin_access["[V19] Gain Administrative Access to HMI"]
    admin_access --> hmi_vuln_exploit
    unauthorized_logic_changes["[H12] Unauthorized Changes to Control Logic"]
    unauthorized_logic_changes --> admin_access
    attacker["[U01] Attacker"]
    attacker --> unauthorized_logic_changes
    engineering_ws_esc["[A12] Engineering Workstation (OS Privileges)"]
    engineering_ws_esc --> privilege_escalation
    os_vulnerability["[V20] OS-Level Vulnerabilities (e.g., Privilege Escalation in Windows/Linux)"]
    os_vulnerability --> engineering_ws_esc
    plc_logic_modification["[H13] Modification of PLC Control Logic via Engineering Workstation"]
    plc_logic_modification --> os_vulnerability
    attacker["[U01] Attacker"]
    attacker --> plc_logic_modification
    lateral_movement["[G07] Move Laterally Across Networks to Compromise Critical Assets"]
    lateral_movement --> root
    it_to_ot_pivot["[A13] IT-OT Network Boundary (Segmentation)"]
    it_to_ot_pivot --> lateral_movement
    weak_segmentation["[V21] Weak or Misconfigured Network Segmentation"]
    weak_segmentation --> it_to_ot_pivot
    corporate_to_control["[V22] Lateral Movement from Corporate Network to Control Network"]
    corporate_to_control --> weak_segmentation
    unauthorized_scada_access["[H14] Unauthorized Access to SCADA System from IT Network"]
    unauthorized_scada_access --> corporate_to_control
    attacker["[U01] Attacker"]
    attacker --> unauthorized_scada_access
    engineering_ws_pivot["[A14] Engineering Workstation (Pivot Point)"]
    engineering_ws_pivot --> lateral_movement
    compromised_ws["[V23] Compromised Engineering Workstation with OT Network Access"]
    compromised_ws --> engineering_ws_pivot
    plc_lateral_access["[H15] Lateral Access to PLC/RTU from Engineering Workstation"]
    plc_lateral_access --> compromised_ws
    malicious_control_commands["[H16] Issuance of Malicious Control Commands to Actuators"]
    malicious_control_commands --> plc_lateral_access
    attacker["[U01] Attacker"]
    attacker --> malicious_control_commands
    supply_chain_risk["[G08] Exploit Supply Chain Vulnerabilities for Persistent Access"]
    supply_chain_risk --> root
    third_party_firmware["[A15] Third-Party Firmware/Software Updates"]
    third_party_firmware --> supply_chain_risk
    malicious_updates["[V24] Malicious Updates from Compromised Vendors"]
    malicious_updates --> third_party_firmware
    plc_backdoor["[H17] Installation of Backdoors in PLC Firmware"]
    plc_backdoor --> malicious_updates
    attacker["[U01] Attacker"]
    attacker --> plc_backdoor
    vendor_remote_access["[A16] Vendor Remote Support Channels"]
    vendor_remote_access --> supply_chain_risk
    unsecured_remote_access["[V25] Unsecured or Over-Permissive Remote Access (e.g., VPN, TeamViewer)"]
    unsecured_remote_access --> vendor_remote_access
    unauthorized_control["[H18] Unauthorized Remote Control of OT Systems by Attacker"]
    unauthorized_control --> unsecured_remote_access
    attacker["[U01] Attacker"]
    attacker --> unauthorized_control
    physical_tampering["[G09] Physically Tamper with Field Devices or Local Systems"]
    physical_tampering --> root
    field_device_access["[A17] Field Devices (Physical Security)"]
    field_device_access --> physical_tampering
    unsecured_ports["[V26] Unsecured Physical Ports (e.g., USB, Serial) on Sensors/Actuators"]
    unsecured_ports --> field_device_access
    local_tampering["[H19] Local Tampering with Sensor/Actuator Configuration"]
    local_tampering --> unsecured_ports
    false_process_data["[H20] Injection of False Process Data via Physical Access"]
    false_process_data --> local_tampering
    attacker["[U01] Attacker"]
    attacker --> false_process_data
    hmi_console_access["[A18] HMI Consoles (Physical Access Control)"]
    hmi_console_access --> physical_tampering
    unattended_sessions["[V27] Unattended or Unlocked HMI Sessions"]
    unattended_sessions --> hmi_console_access
    unauthorized_manual_override["[H21] Unauthorized Manual Override of Control Processes"]
    unauthorized_manual_override --> unattended_sessions
    attacker["[U01] Attacker"]
    attacker --> unauthorized_manual_override