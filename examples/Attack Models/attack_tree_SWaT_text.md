graph BT
    root["[G00] Disrupt or Stop SWaT Cyber-Physical System Operations via Compromise of Control Logic, Data Integrity, or Availability"]
    compromise_plc_logic["[G01] Compromise PLC Control Logic to Disrupt Physical Processes"]
    compromise_plc_logic --> root
    plc_firmware_exploit["[V01] Exploit PLC Firmware Vulnerabilities (e.g., CVE-2019-10955 in Schneider Modicon)"]
    plc_firmware_exploit --> compromise_plc_logic
    plc_firmware_remote_code_execution["[V02] Achieve Remote Code Execution via Buffer Overflow in EtherNet/IP Stack"]
    plc_firmware_remote_code_execution --> plc_firmware_exploit
    plc_unauthenticated_access["[V03] Exploit Lack of Authentication in PLC Communication Protocol"]
    plc_unauthenticated_access --> plc_firmware_remote_code_execution
    attacker["[U01] Attacker"]
    attacker --> plc_unauthenticated_access
    plc_default_credentials["[V04] Exploit Default or Weak Credentials in PLC Engineering Interface"]
    plc_default_credentials --> plc_firmware_remote_code_execution
    attacker["[U01] Attacker"]
    attacker --> plc_default_credentials
    plc_logic_tampering["[V05] Tamper with PLC Ladder Logic via Authorized Upload Interfaces"]
    plc_logic_tampering --> compromise_plc_logic
    insider_threat_plc["[H01] Insider Threat: Authorized User Uploads Malicious or Flawed Control Logic"]
    insider_threat_plc --> plc_logic_tampering
    plc_logic_backdoor["[A01] Malicious Logic with Hidden Triggers or Time Delays"]
    plc_logic_backdoor --> insider_threat_plc
    attacker["[U01] Attacker"]
    attacker --> plc_logic_backdoor
    supply_chain_compromise["[H02] Supply Chain Compromise: Pre-installed Backdoors in PLC Firmware"]
    supply_chain_compromise --> plc_logic_tampering
    third_party_plc_firmware["[A02] Compromised Allen-Bradley or Schneider PLC Firmware"]
    third_party_plc_firmware --> supply_chain_compromise
    attacker["[U01] Attacker"]
    attacker --> third_party_plc_firmware
    compromise_hmi_scada["[G02] Compromise HMI/SCADA to Disrupt Monitoring or Issue Unauthorized Commands"]
    compromise_hmi_scada --> root
    hmi_spoofing["[V06] Spoof HMI Commands via Session Hijacking or Replay Attacks"]
    hmi_spoofing --> compromise_hmi_scada
    hmi_weak_auth["[V07] Exploit Weak or Missing Multi-Factor Authentication in HMI"]
    hmi_weak_auth --> hmi_spoofing
    hmi_credential_theft["[V08] Steal Operator Credentials via Keylogging or Phishing"]
    hmi_credential_theft --> hmi_weak_auth
    attacker["[U01] Attacker"]
    attacker --> hmi_credential_theft
    hmi_protocol_vuln["[V09] Exploit Vulnerabilities in HMI-PLC Protocols (e.g., CVE-2018-10622 in Modbus TCP)"]
    hmi_protocol_vuln --> hmi_spoofing
    hmi_man_in_the_middle["[V10] Perform Man-in-the-Middle Attack on HMI-PLC Communication"]
    hmi_man_in_the_middle --> hmi_protocol_vuln
    attacker["[U01] Attacker"]
    attacker --> hmi_man_in_the_middle
    scada_data_tampering["[V11] Tamper with SCADA Data Logs or Historian Records"]
    scada_data_tampering --> compromise_hmi_scada
    scada_sql_injection["[V12] Exploit SQL Injection in Historian Database (e.g., OSIsoft PI)"]
    scada_sql_injection --> scada_data_tampering
    scada_unauth_access["[V13] Gain Unauthorized Access to Historian via Misconfigured Permissions"]
    scada_unauth_access --> scada_sql_injection
    attacker["[U01] Attacker"]
    attacker --> scada_unauth_access
    scada_log_deletion["[H03] Delete or Alter Logs to Hide Malicious Activities (Repudiation)"]
    scada_log_deletion --> scada_data_tampering
    scada_admin_privileges["[V14] Escalate Privileges to Administrator via Exploits (e.g., CVE-2017-12717)"]
    scada_admin_privileges --> scada_log_deletion
    attacker["[U01] Attacker"]
    attacker --> scada_admin_privileges
    disrupt_communications["[G03] Disrupt OT/IT Network Communications to Cause Denial-of-Service (DoS)"]
    disrupt_communications --> root
    enip_dos["[V15] Exploit EtherNet/IP Protocol Vulnerabilities to Crash PLCs/RIOs"]
    enip_dos --> disrupt_communications
    enip_flood_attack["[V16] Flood PLCs with Malformed ENIP Packets to Cause Fault State"]
    enip_flood_attack --> enip_dos
    attacker["[U01] Attacker"]
    attacker --> enip_flood_attack
    wireless_exploitation["[V17] Exploit Wireless Access Points (WAPs) to Disrupt or Eavesdrop on Communications"]
    wireless_exploitation --> disrupt_communications
    wap_rogue_access["[V18] Deploy Rogue WAP to Intercept or Inject Traffic"]
    wap_rogue_access --> wireless_exploitation
    wap_weak_encryption["[V19] Crack Weak Wireless Encryption (e.g., WEP/WPA2-PSK)"]
    wap_weak_encryption --> wap_rogue_access
    attacker["[U01] Attacker"]
    attacker --> wap_weak_encryption
    wap_dos["[H04] Launch Deauthentication Attacks to Disrupt Wireless HMI/PLC Comm"]
    wap_dos --> wireless_exploitation
    attacker["[U01] Attacker"]
    attacker --> wap_dos
    compromise_field_devices["[G04] Compromise Field Devices (RIOs/Sensors/Actuators) to Disrupt Process Control"]
    compromise_field_devices --> root
    rio_tampering["[V20] Tamper with Schneider RIO Units to Send False Sensor Data"]
    rio_tampering --> compromise_field_devices
    rio_physical_access["[H05] Gain Physical Access to RIO Units for Direct Tampering"]
    rio_physical_access --> rio_tampering
    rio_firmware_flash["[A03] Flash Compromised Firmware via USB or Serial Interface"]
    rio_firmware_flash --> rio_physical_access
    attacker["[U01] Attacker"]
    attacker --> rio_firmware_flash
    rio_protocol_exploit["[V21] Exploit Vulnerabilities in RIO-PLC Communication Protocol"]
    rio_protocol_exploit --> rio_tampering
    rio_replay_attack["[V22] Replay Legitimate RIO Traffic to Spoof Sensor Readings"]
    rio_replay_attack --> rio_protocol_exploit
    attacker["[U01] Attacker"]
    attacker --> rio_replay_attack
    sensor_actuator_spoofing["[H06] Spoof Sensor/Actuator Signals to Trigger Unsafe Process States"]
    sensor_actuator_spoofing --> compromise_field_devices
    sensor_false_data["[A04] Inject False Sensor Data (e.g., Fake High Pressure Readings)"]
    sensor_false_data --> sensor_actuator_spoofing
    attacker["[U01] Attacker"]
    attacker --> sensor_false_data
    actuator_unauthorized_control["[A05] Send Unauthorized Commands to Actuators (e.g., Open/Close Valves)"]
    actuator_unauthorized_control --> sensor_actuator_spoofing
    attacker["[U01] Attacker"]
    attacker --> actuator_unauthorized_control
    exploit_testbed_interconnections["[G05] Exploit Interconnected Testbeds for Lateral Movement or Shared Vulnerabilities"]
    exploit_testbed_interconnections --> root
    testbed_lateral_movement["[V23] Move Laterally from Compromised Adjacent Testbed to SWaT"]
    testbed_lateral_movement --> exploit_testbed_interconnections
    shared_protocol_exploit["[V24] Exploit Shared Protocols (e.g., ENIP, Modbus) Across Testbeds"]
    shared_protocol_exploit --> testbed_lateral_movement
    testbed_trust_exploitation["[H07] Abuse Trust Relationships Between Interconnected Testbeds"]
    testbed_trust_exploitation --> shared_protocol_exploit
    attacker["[U01] Attacker"]
    attacker --> testbed_trust_exploitation
    testbed_supply_chain["[H08] Compromise Shared Third-Party Components (e.g., PLCs, RIOs) in Testbeds"]
    testbed_supply_chain --> exploit_testbed_interconnections
    shared_firmware_vuln["[A06] Vulnerable Firmware Shared Across Multiple Testbeds"]
    shared_firmware_vuln --> testbed_supply_chain
    attacker["[U01] Attacker"]
    attacker --> shared_firmware_vuln
    physical_sabotage["[G06] Physically Sabotage Hardware or Introduce Malicious Media"]
    physical_sabotage --> root
    plc_hmi_usb_attack["[H09] Introduce Malicious USB Media into PLC/HMI Engineering Workstations"]
    plc_hmi_usb_attack --> physical_sabotage
    usb_firmware_flash["[A07] Use USB to Flash Malicious PLC Firmware or Ladder Logic"]
    usb_firmware_flash --> plc_hmi_usb_attack
    attacker["[U01] Attacker"]
    attacker --> usb_firmware_flash
    hardware_tampering["[H10] Physically Tamper with PLCs/RIOs to Install Hardware Trojans"]
    hardware_tampering --> physical_sabotage
    plc_hardware_backdoor["[A08] Install Hardware-Based Backdoor in PLC (e.g., FPGA Trojan)"]
    plc_hardware_backdoor --> hardware_tampering
    attacker["[U01] Attacker"]
    attacker --> plc_hardware_backdoor