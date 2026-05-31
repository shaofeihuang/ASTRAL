graph BT
    root["[G01] CPS Disruption in Medical Cyber-Physical Systems"]
    spoofing_medical_device["[H01] Spoofing of Legitimate Medical Devices"]
    spoofing_medical_device --> root
    weak_auth_mechanism["[V01] Weak Authentication in Device-Control System Communication"]
    weak_auth_mechanism --> spoofing_medical_device
    modbus_no_auth["[A01] Modbus TCP Without Authentication"]
    modbus_no_auth --> weak_auth_mechanism
    attacker["[U01] Attacker"]
    attacker --> modbus_no_auth
    opc_ua_misconfig["[A02] Misconfigured OPC UA Certificates"]
    opc_ua_misconfig --> weak_auth_mechanism
    attacker --> opc_ua_misconfig
    falsified_sensor_data["[H02] Falsified Sensor Data Injection"]
    falsified_sensor_data --> spoofing_medical_device
    unvalidated_input_hmi["[V02] Unvalidated Input at HMI Level"]
    unvalidated_input_hmi --> falsified_sensor_data
    hmi_software_vuln["[A03] Vulnerable HMI Software (e.g., CVE-2020-25159)"]
    hmi_software_vuln --> unvalidated_input_hmi
    attacker --> hmi_software_vuln
    tampering_firmware["[H03] Tampering with Medical Device Firmware"]
    tampering_firmware --> root
    insecure_fw_update["[V03] Insecure Firmware Update Mechanism"]
    insecure_fw_update --> tampering_firmware
    unencrypted_fw_channel["[A04] Unencrypted Firmware Update Channel"]
    unencrypted_fw_channel --> insecure_fw_update
    attacker --> unencrypted_fw_channel
    default_credentials_fw["[A05] Default Credentials in Firmware Update Portal"]
    default_credentials_fw --> insecure_fw_update
    attacker --> default_credentials_fw
    physical_tampering["[H04] Physical Tampering with Medical Devices"]
    physical_tampering --> tampering_firmware
    unsecured_usb_ports["[A06] Unsecured USB Ports on Medical Devices"]
    unsecured_usb_ports --> physical_tampering
    attacker --> unsecured_usb_ports
    unlocked_debug_consoles["[A07] Unlocked Debug Consoles (e.g., JTAG, UART)"]
    unlocked_debug_consoles --> physical_tampering
    attacker --> unlocked_debug_consoles
    repudiation_actions["[H05] Repudiation of Malicious Actions"]
    repudiation_actions --> root
    insufficient_logging["[V04] Insufficient Logging and Monitoring"]
    insufficient_logging --> repudiation_actions
    disabled_audit_logs["[A08] Disabled Audit Logs on Critical Devices"]
    disabled_audit_logs --> insufficient_logging
    attacker --> disabled_audit_logs
    unencrypted_log_storage["[A09] Unencrypted Log Storage"]
    unencrypted_log_storage --> insufficient_logging
    attacker --> unencrypted_log_storage
    compromised_operator_creds["[V05] Compromised Operator Credentials"]
    compromised_operator_creds --> repudiation_actions
    weak_password_policies["[A10] Weak Password Policies for OT Access"]
    weak_password_policies --> compromised_operator_creds
    attacker --> weak_password_policies
    info_disclosure["[H06] Unauthorized Information Disclosure"]
    info_disclosure --> root
    weak_network_encryption["[V06] Weak Network Encryption"]
    weak_network_encryption --> info_disclosure
    outdated_tls_ot["[A11] Outdated TLS in OT Protocols (e.g., Modbus/TLS 1.0)"]
    outdated_tls_ot --> weak_network_encryption
    attacker --> outdated_tls_ot
    exposed_api_endpoints["[V07] Exposed API Endpoints in DMZ"]
    exposed_api_endpoints --> info_disclosure
    unauthenticated_opc_ua["[A12] Unauthenticated OPC UA Endpoints"]
    unauthenticated_opc_ua --> exposed_api_endpoints
    attacker --> unauthenticated_opc_ua
    dos_medical_services["[H07] Denial of Service in Medical Services"]
    dos_medical_services --> root
    network_flooding["[V08] Network Flooding Vulnerabilities"]
    network_flooding --> dos_medical_services
    unsegmented_ot_network["[A13] Unsegmented OT Network Allowing Broadcast Storms"]
    unsegmented_ot_network --> network_flooding
    attacker --> unsegmented_ot_network
    protocol_specific_dos["[V09] Protocol-Specific DoS (e.g., Modbus, DICOM)"]
    protocol_specific_dos --> dos_medical_services
    modbus_malformed_packets["[A14] Modbus Malformed Packet Handling Vulnerabilities"]
    modbus_malformed_packets --> protocol_specific_dos
    attacker --> modbus_malformed_packets
    privilege_escalation["[H08] Elevation of Privilege in Medical CPS"]
    privilege_escalation --> root
    vulnerable_ot_software["[V10] Vulnerable OT Software (e.g., CVE-2018-14847)"]
    vulnerable_ot_software --> privilege_escalation
    unpatched_plc_firmware["[A15] Unpatched PLC Firmware"]
    unpatched_plc_firmware --> vulnerable_ot_software
    attacker --> unpatched_plc_firmware
    misconfigured_rbac["[V11] Misconfigured Role-Based Access Control (RBAC)"]
    misconfigured_rbac --> privilege_escalation
    overprivileged_service_accounts["[A16] Overprivileged Service Accounts in OT"]
    overprivileged_service_accounts --> misconfigured_rbac
    attacker --> overprivileged_service_accounts
    lateral_movement["[H09] Lateral Movement Across Purdue Levels"]
    lateral_movement --> root
    weak_segmentation["[V12] Weak Segmentation Between IT/OT Zones"]
    weak_segmentation --> lateral_movement
    flat_ot_network["[A17] Flat OT Network Topology"]
    flat_ot_network --> weak_segmentation
    attacker --> flat_ot_network
    unmonitored_vlans["[A18] Unmonitored VLANs Between Levels 3 and 2"]
    unmonitored_vlans --> weak_segmentation
    attacker --> unmonitored_vlans
    compromised_gateway["[V13] Compromised IT-OT Gateway (e.g., OPC UA Proxy)"]
    compromised_gateway --> lateral_movement
    default_creds_gateway["[A19] Default Credentials on IT-OT Gateway"]
    default_creds_gateway --> compromised_gateway
    attacker --> default_creds_gateway
    supply_chain_risks["[H10] Supply Chain Compromise"]
    supply_chain_risks --> root
    third_party_firmware["[V14] Malicious Third-Party Firmware Updates"]
    third_party_firmware --> supply_chain_risks
    unverified_vendor_updates["[A20] Unverified Vendor-Signed Firmware"]
    unverified_vendor_updates --> third_party_firmware
    attacker --> unverified_vendor_updates
    pre_compromised_devices["[V15] Pre-Compromised Medical Devices (e.g., Implanted Backdoors)"]
    pre_compromised_devices --> supply_chain_risks
    cots_default_backdoors["[A21] Default Backdoors in COTS Medical Devices"]
    cots_default_backdoors --> pre_compromised_devices
    attacker --> cots_default_backdoors
    insider_threats["[H11] Insider Threats (Privileged Access Abuse)"]
    insider_threats --> root
    abuse_of_privileged_access["[V16] Abuse of Privileged OT Access"]
    abuse_of_privileged_access --> insider_threats
    unmonitored_admin_workstations["[A22] Unmonitored Admin Workstations with OT Access"]
    unmonitored_admin_workstations --> abuse_of_privileged_access
    attacker --> unmonitored_admin_workstations
    social_engineering_ot["[V17] Social Engineering Targeting OT Operators"]
    social_engineering_ot --> insider_threats
    phishing_ot_creds["[A23] Phishing for OT Operator Credentials"]
    phishing_ot_creds --> social_engineering_ot
    attacker --> phishing_ot_creds
    wireless_exploitation["[H12] Exploitation of Wireless Medical Interfaces"]
    wireless_exploitation --> root
    unsecured_wireless_protocols["[V18] Unsecured Wireless Protocols (e.g., BLE, Zigbee)"]
    unsecured_wireless_protocols --> wireless_exploitation
    ble_no_encryption["[A24] BLE Devices Without Encryption"]
    ble_no_encryption --> unsecured_wireless_protocols
    attacker --> ble_no_encryption
    default_zigbee_keys["[A25] Default Zigbee Network Keys"]
    default_zigbee_keys --> unsecured_wireless_protocols
    attacker --> default_zigbee_keys
    rogue_wireless_ap["[V19] Rogue Wireless Access Points in Medical Zones"]
    rogue_wireless_ap --> wireless_exploitation
    unauthorized_wifi_iot["[A26] Unauthorized Wi-Fi on Medical IoT Devices"]
    unauthorized_wifi_iot --> rogue_wireless_ap
    attacker --> unauthorized_wifi_iot