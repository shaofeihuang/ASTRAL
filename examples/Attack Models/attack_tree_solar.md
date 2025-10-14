graph BT
    root["[G01] Disrupt or Stop Cyber-Physical System Operations (Heating System)"]
    spoofing["[H01] Spoofing of Control Commands or Sensor Data"]
    spoofing --> root
    modbus_spoof["[V01] Exploit Weak Authentication in Modbus/TCP (CVE-2018-5443)"]
    modbus_spoof --> spoofing
    plc_compromise["[A01] Programmable Logic Controllers (PLCs)"]
    plc_compromise --> modbus_spoof
    plc_firmware["[V02] Outdated or Vulnerable PLC Firmware"]
    plc_firmware --> plc_compromise
    attacker["[U01] Attacker"]
    attacker --> plc_firmware
    plc_default_creds["[V03] Default or Weak Credentials on PLCs"]
    plc_default_creds --> plc_compromise
    attacker["[U01] Attacker"]
    attacker --> plc_default_creds
    dnp3_spoof["[V04] Exploit Lack of Authentication in DNP3 Protocol"]
    dnp3_spoof --> spoofing
    rtu_compromise["[A02] Remote Terminal Units (RTUs)"]
    rtu_compromise --> dnp3_spoof
    rtu_mitm["[H02] Man-in-the-Middle (MITM) Attack on RTU Communications"]
    rtu_mitm --> rtu_compromise
    attacker["[U01] Attacker"]
    attacker --> rtu_mitm
    tampering["[H03] Tampering with System Parameters or Data"]
    tampering --> root
    hmi_tamper["[A03] Human-Machine Interface (HMI)"]
    hmi_tamper --> tampering
    hmi_input_val["[V05] Improper Input Validation in HMI (CVE-2017-9642)"]
    hmi_input_val --> hmi_tamper
    hmi_cred_theft["[V06] Stolen or Weak HMI Operator Credentials"]
    hmi_cred_theft --> hmi_input_val
    attacker["[U01] Attacker"]
    attacker --> hmi_cred_theft
    scada_log_tamper["[A04] SCADA System Logs"]
    scada_log_tamper --> tampering
    scada_log_integrity["[V07] Compromised Log Integrity (CVE-2019-10995)"]
    scada_log_integrity --> scada_log_tamper
    scada_priv_escalation["[V08] Privilege Escalation in SCADA (CVE-2018-10617)"]
    scada_priv_escalation --> scada_log_integrity
    attacker["[U01] Attacker"]
    attacker --> scada_priv_escalation
    repudiation["[H04] Repudiation via Log or Audit Trail Manipulation"]
    repudiation --> root
    scada_audit_bypass["[A05] SCADA Audit Mechanisms"]
    scada_audit_bypass --> repudiation
    scada_weak_logging["[V09] Insufficient Logging or Log Tampering"]
    scada_weak_logging --> scada_audit_bypass
    scada_cred_compromise["[V10] Compromised SCADA Administrator Credentials"]
    scada_cred_compromise --> scada_weak_logging
    attacker["[U01] Attacker"]
    attacker --> scada_cred_compromise
    info_disclosure["[H05] Information Disclosure of Sensitive Data"]
    info_disclosure --> root
    web_interface["[A06] Heating System Web Interface"]
    web_interface --> info_disclosure
    web_vuln["[V11] Web Interface Information Disclosure (CVE-2020-7014)"]
    web_vuln --> web_interface
    web_default_creds["[V12] Default Credentials on Web Interface"]
    web_default_creds --> web_vuln
    attacker["[U01] Attacker"]
    attacker --> web_default_creds
    unencrypted_comms["[A07] Unencrypted Communications (Modbus, DNP3)"]
    unencrypted_comms --> info_disclosure
    sniffing["[H06] Network Traffic Sniffing"]
    sniffing --> unencrypted_comms
    network_access["[A08] Access to OT Network Segment"]
    network_access --> sniffing
    attacker["[U01] Attacker"]
    attacker --> network_access
    dos["[H07] Denial of Service (DoS) on Critical Components"]
    dos --> root
    network_flood["[H08] Network Flooding Attack"]
    network_flood --> dos
    plc_comms["[A09] PLC Communication Channels"]
    plc_comms --> network_flood
    plc_dos_vuln["[V13] PLC DoS Vulnerability (CVE-2016-5694)"]
    plc_dos_vuln --> plc_comms
    attacker["[U01] Attacker"]
    attacker --> plc_dos_vuln
    scada_overload["[A10] SCADA System Resources"]
    scada_overload --> dos
    scada_resource_exhaustion["[H09] SCADA Resource Exhaustion"]
    scada_resource_exhaustion --> scada_overload
    malicious_payload["[V14] Malicious Payload via Engineering Workstation"]
    malicious_payload --> scada_resource_exhaustion
    attacker["[U01] Attacker"]
    attacker --> malicious_payload
    priv_escalation["[H10] Elevation of Privilege"]
    priv_escalation --> root
    auth_mechanism["[A11] Authentication Mechanism in OT Systems"]
    auth_mechanism --> priv_escalation
    auth_bypass["[V15] Authentication Bypass (CVE-2018-10617)"]
    auth_bypass --> auth_mechanism
    cred_theft["[H11] Theft of Operator/Administrator Credentials"]
    cred_theft --> auth_bypass
    attacker["[U01] Attacker"]
    attacker --> cred_theft
    lateral_movement["[H12] Lateral Movement Across OT Network"]
    lateral_movement --> root
    hmi_compromise["[A12] Compromised HMI Workstation"]
    hmi_compromise --> lateral_movement
    hmi_to_plc["[H13] Pivot from HMI to PLC/RTU"]
    hmi_to_plc --> hmi_compromise
    weak_segmentation["[V16] Inadequate Network Segmentation"]
    weak_segmentation --> hmi_to_plc
    attacker["[U01] Attacker"]
    attacker --> weak_segmentation
    engineering_ws["[A13] Engineering Workstation"]
    engineering_ws --> lateral_movement
    malware_injection["[V17] Malware Injection via Engineering Tools"]
    malware_injection --> engineering_ws
    firmware_backdoor["[V18] Backdoored Firmware Updates"]
    firmware_backdoor --> malware_injection
    attacker["[U01] Attacker"]
    attacker --> firmware_backdoor
    supply_chain["[H14] Supply Chain Compromise"]
    supply_chain --> root
    vendor_access["[A14] Vendor Remote Access Tools"]
    vendor_access --> supply_chain
    vendor_cred_compromise["[V19] Compromised Vendor Credentials or Tools"]
    vendor_cred_compromise --> vendor_access
    malicious_update["[V20] Malicious Firmware/Software Update (SolarWinds-style)"]
    malicious_update --> vendor_cred_compromise
    attacker["[U01] Attacker"]
    attacker --> malicious_update
    counterfeit_hw["[A15] Counterfeit or Tampered Hardware"]
    counterfeit_hw --> supply_chain
    plc_backdoor["[V21] Hardware Backdoors in PLCs/RTUs"]
    plc_backdoor --> counterfeit_hw
    attacker["[U01] Attacker"]
    attacker --> plc_backdoor
    physical_access["[H15] Physical Access Exploitation"]
    physical_access --> root
    plc_console["[A16] PLC/RUT Console Ports"]
    plc_console --> physical_access
    default_console_creds["[V22] Default Console Credentials"]
    default_console_creds --> plc_console
    attacker["[U01] Attacker"]
    attacker --> default_console_creds
    usb_drops["[A17] USB Ports on HMIs/Engineering Workstations"]
    usb_drops --> physical_access
    malicious_usb["[H16] Malicious USB Device (BadUSB, Rubber Ducky)"]
    malicious_usb --> usb_drops
    attacker["[U01] Attacker"]
    attacker --> malicious_usb
    field_devices["[A18] Field Devices (Sensors/Actuators)"]
    field_devices --> physical_access
    signal_injection["[H17] Signal Injection or Tampering"]
    signal_injection --> field_devices
    unsecured_wiring["[V23] Unsecured or Exposed Wiring"]
    unsecured_wiring --> signal_injection
    attacker["[U01] Attacker"]
    attacker --> unsecured_wiring
    social_engineering["[H18] Social Engineering of Operators/Vendors"]
    social_engineering --> root
    phishing["[A19] Operator Email or Messaging Systems"]
    phishing --> social_engineering
    fake_maintenance["[H19] Fake Maintenance Requests or Alerts"]
    fake_maintenance --> phishing
    operator_action["[H20] Coerced Operator Action (e.g., Disable Alarms)"]
    operator_action --> fake_maintenance
    attacker["[U01] Attacker"]
    attacker --> operator_action
    vendor_impersonation["[A20] Vendor Support Channels"]
    vendor_impersonation --> social_engineering
    fake_vendor["[H21] Impersonation of Vendor Support"]
    fake_vendor --> vendor_impersonation
    remote_access_abuse["[V24] Abuse of Legitimate Remote Access Tools"]
    remote_access_abuse --> fake_vendor
    attacker["[U01] Attacker"]
    attacker --> remote_access_abuse
    time_sync_attack["[H22] Time Synchronization Attack"]
    time_sync_attack --> root
    ntp_spoofing["[A21] NTP Server or Protocol"]
    ntp_spoofing --> time_sync_attack
    ntp_vulnerability["[V25] NTP Spoofing or MITM (CVE-2013-5211)"]
    ntp_vulnerability --> ntp_spoofing
    time_desync["[H23] Desynchronized Clocks on OT Devices"]
    time_desync --> ntp_vulnerability
    attacker["[U01] Attacker"]
    attacker --> time_desync