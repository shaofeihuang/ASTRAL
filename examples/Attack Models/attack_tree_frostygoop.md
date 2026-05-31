graph BT
    root["[G01] CPS Disruption: Compromise of District Heating System Operations"]
    spoofing_root["[H01] Spoofing Attacks Leading to Unauthorized Control Actions"]
    spoofing_root --> root
    spoof_hmi_commands["[H02] Spoofing of HMI Commands via Weak Authentication"]
    spoof_hmi_commands --> spoofing_root
    hmi_weak_auth["[V01] Weak Authentication in HMI (e.g., Default Credentials, No MFA)"]
    hmi_weak_auth --> spoof_hmi_commands
    hmi_software_vuln["[V02] HMI Software Vulnerability (e.g., CVE-2018-10622 in GE HMI)"]
    hmi_software_vuln --> hmi_weak_auth
    attacker["[U01] Attacker"]
    attacker --> hmi_software_vuln
    hmi_spoofed_setpoints["[A01] Spoofed Temperature Setpoints Sent to PLCs"]
    hmi_spoofed_setpoints --> spoof_hmi_commands
    plc_unauth_commands["[V03] PLCs Accepting Unauthenticated Commands"]
    plc_unauth_commands --> hmi_spoofed_setpoints
    attacker --> plc_unauth_commands
    spoof_scada_credentials["[H03] Spoofing via Compromised SCADA Credentials"]
    spoof_scada_credentials --> spoofing_root
    scada_cred_theft["[V04] Theft of SCADA Credentials (Phishing, Keylogging)"]
    scada_cred_theft --> spoof_scada_credentials
    attacker --> scada_cred_theft
    scada_spoofed_commands["[A02] Spoofed Control Commands to PLCs/RTUs"]
    scada_spoofed_commands --> spoof_scada_credentials
    plc_no_command_auth["[V05] Lack of Command Authentication in PLCs"]
    plc_no_command_auth --> scada_spoofed_commands
    attacker --> plc_no_command_auth
    tampering_root["[H04] Tampering with Sensor Data or Control Logic"]
    tampering_root --> root
    tamper_sensor_data["[H05] Tampering with Sensor Data in Transit"]
    tamper_sensor_data --> tampering_root
    fieldbus_no_integrity["[V06] Lack of Integrity Checks in Fieldbus (Modbus, Profibus)"]
    fieldbus_no_integrity --> tamper_sensor_data
    attacker --> fieldbus_no_integrity
    fake_sensor_readings["[A03] Falsified Temperature/Pressure Readings Sent to PLCs"]
    fake_sensor_readings --> tamper_sensor_data
    plc_trusts_sensor_data["[V07] PLCs Trust Sensor Data Without Validation"]
    plc_trusts_sensor_data --> fake_sensor_readings
    attacker --> plc_trusts_sensor_data
    tamper_plc_firmware["[H06] Tampering with PLC/RTU Firmware"]
    tamper_plc_firmware --> tampering_root
    plc_firmware_vuln["[V08] Vulnerable PLC Firmware (e.g., CVE-2017-12736 in Siemens)"]
    plc_firmware_vuln --> tamper_plc_firmware
    attacker --> plc_firmware_vuln
    modified_control_logic["[A04] Altered Control Logic Causing Unsafe Operations"]
    modified_control_logic --> tamper_plc_firmware
    plc_no_firmware_signing["[V09] Lack of Firmware Signing/Verification in PLCs"]
    plc_no_firmware_signing --> modified_control_logic
    attacker --> plc_no_firmware_signing
    repudiation_root["[H07] Repudiation: Unlogged or Anonymous Malicious Actions"]
    repudiation_root --> root
    no_logging_mechanisms["[V10] Lack of Comprehensive Logging in SCADA/HMI"]
    no_logging_mechanisms --> repudiation_root
    attacker --> no_logging_mechanisms
    anonymous_opc_ua["[V11] OPC UA Misconfigured to Allow Anonymous Access"]
    anonymous_opc_ua --> repudiation_root
    attacker --> anonymous_opc_ua
    unlogged_plc_changes["[A05] Unlogged Changes to PLC Control Logic"]
    unlogged_plc_changes --> repudiation_root
    plc_no_audit_logs["[V12] PLCs Lack Audit Logging for Logic Changes"]
    plc_no_audit_logs --> unlogged_plc_changes
    attacker --> plc_no_audit_logs
    info_disclosure_root["[H08] Information Disclosure Leading to Further Attacks"]
    info_disclosure_root --> root
    hmi_info_leak["[V13] HMI Software Information Leak (e.g., CVE-2018-10622)"]
    hmi_info_leak --> info_disclosure_root
    attacker --> hmi_info_leak
    scada_db_access["[A06] Unauthorized Access to SCADA Database (Historian)"]
    scada_db_access --> info_disclosure_root
    scada_db_weak_auth["[V14] Weak Authentication for SCADA Database Access"]
    scada_db_weak_auth --> scada_db_access
    attacker --> scada_db_weak_auth
    network_sniffing["[H09] Passive Network Sniffing of Unencrypted OT Traffic"]
    network_sniffing --> info_disclosure_root
    unencrypted_fieldbus["[V15] Unencrypted Fieldbus Traffic (Modbus, Profibus)"]
    unencrypted_fieldbus --> network_sniffing
    attacker --> unencrypted_fieldbus
    dos_root["[H10] Denial of Service (DoS) Disrupting System Operations"]
    dos_root --> root
    network_flooding["[H11] Network Flooding Attack on OT Infrastructure"]
    network_flooding --> dos_root
    no_ot_dos_protection["[V16] Lack of DoS Protection in OT Networks"]
    no_ot_dos_protection --> network_flooding
    attacker --> no_ot_dos_protection
    disrupted_plc_comms["[A07] Disrupted Communication Between PLCs and SCADA"]
    disrupted_plc_comms --> network_flooding
    plc_no_redundancy["[V17] Lack of Redundant Communication Paths for PLCs"]
    plc_no_redundancy --> disrupted_plc_comms
    attacker --> plc_no_redundancy
    rtu_crash["[H12] Crashing of RTUs via Exploited Vulnerabilities"]
    rtu_crash --> dos_root
    rtu_firmware_vuln["[V18] Vulnerable RTU Firmware (e.g., Buffer Overflow)"]
    rtu_firmware_vuln --> rtu_crash
    attacker --> rtu_firmware_vuln
    rtu_unresponsive["[A08] RTUs Become Unresponsive to SCADA Commands"]
    rtu_unresponsive --> rtu_crash
    scada_no_rtu_failover["[V19] SCADA Lacks RTU Failover Mechanisms"]
    scada_no_rtu_failover --> rtu_unresponsive
    attacker --> scada_no_rtu_failover
    priv_escalation_root["[H13] Privilege Escalation in SCADA/OT Systems"]
    priv_escalation_root --> root
    scada_priv_esc["[V20] SCADA Software Privilege Escalation Vulnerability"]
    scada_priv_esc --> priv_escalation_root
    attacker --> scada_priv_esc
    engineering_ws_access["[A09] Unauthorized Access to Engineering Workstation"]
    engineering_ws_access --> priv_escalation_root
    ws_weak_access_control["[V21] Weak Access Control on Engineering Workstations"]
    ws_weak_access_control --> engineering_ws_access
    attacker --> ws_weak_access_control
    plc_logic_modified["[A10] Malicious Modification of PLC Control Logic"]
    plc_logic_modified --> engineering_ws_access
    plc_no_logic_integrity["[V22] Lack of Integrity Checks for PLC Logic Uploads"]
    plc_no_logic_integrity --> plc_logic_modified
    attacker --> plc_no_logic_integrity
    lateral_movement_root["[H14] Lateral Movement from IT to OT Networks"]
    lateral_movement_root --> root
    it_ot_seg_bypass["[V23] Bypassing IT-OT Segmentation (Firewall Misconfig, VPN Exploits)"]
    it_ot_seg_bypass --> lateral_movement_root
    attacker --> it_ot_seg_bypass
    compromised_gateway["[A11] Compromised OT-IT Gateway (e.g., OPC UA Broker)"]
    compromised_gateway --> lateral_movement_root
    gateway_weak_auth["[V24] Weak Authentication on OT-IT Gateway"]
    gateway_weak_auth --> compromised_gateway
    attacker --> gateway_weak_auth
    ot_network_access["[A12] Unauthorized Access to OT Network via Gateway"]
    ot_network_access --> compromised_gateway
    ot_no_network_monitoring["[V25] Lack of Network Monitoring in OT Segments"]
    ot_no_network_monitoring --> ot_network_access
    attacker --> ot_no_network_monitoring
    physical_tampering_root["[H15] Physical Tampering with Field Devices"]
    physical_tampering_root --> root
    unsecured_field_devices["[V26] Unsecured Physical Access to Sensors/Actuators"]
    unsecured_field_devices --> physical_tampering_root
    attacker --> unsecured_field_devices
    plc_console_access["[A13] Unauthorized Access to PLC Serial Console"]
    plc_console_access --> physical_tampering_root
    plc_no_console_auth["[V27] Lack of Authentication for PLC Console Access"]
    plc_no_console_auth --> plc_console_access
    attacker --> plc_no_console_auth
    plc_firmware_flash["[A14] Malicious Firmware Flash via PLC Console"]
    plc_firmware_flash --> plc_console_access
    plc_no_firmware_auth["[V28] Lack of Authentication for Firmware Updates"]
    plc_no_firmware_auth --> plc_firmware_flash
    attacker --> plc_no_firmware_auth
    supply_chain_root["[H16] Supply Chain Attacks via Malicious Components"]
    supply_chain_root --> root
    counterfeit_plc_modules["[V29] Counterfeit or Malicious PLC Hardware Modules"]
    counterfeit_plc_modules --> supply_chain_root
    attacker --> counterfeit_plc_modules
    malicious_firmware_update["[A15] Malicious Firmware Update from Compromised Vendor"]
    malicious_firmware_update --> supply_chain_root
    no_firmware_verification["[V30] Lack of Cryptographic Verification for Firmware Updates"]
    no_firmware_verification --> malicious_firmware_update
    attacker --> no_firmware_verification