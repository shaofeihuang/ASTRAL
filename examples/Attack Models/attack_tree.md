graph BT
    root["[G01] Disrupt or Stop Solar PV Cyber-Physical System Operations"]
    compromise_ot_control["[G02] Compromise OT Control of Inverter/PLC Systems"]
    compromise_ot_control --> root
    exploit_network_vulnerabilities["[G03] Exploit Network-Based Vulnerabilities in OT Protocols"]
    exploit_network_vulnerabilities --> compromise_ot_control
    modbus_tcp_exploit["[V01] Exploit Modbus/TCP Authentication Bypass (CVE-2022-3169)"]
    modbus_tcp_exploit --> exploit_network_vulnerabilities
    modbus_interface["[A01] Modbus/TCP Interface (Port 502)"]
    modbus_interface --> modbus_tcp_exploit
    attacker["[U01] Attacker"]
    attacker --> modbus_interface
    dnp3_dos["[V02] Exploit DNP3 DoS Vulnerability (CVE-2019-18272)"]
    dnp3_dos --> exploit_network_vulnerabilities
    dnp3_interface["[A02] DNP3 Communication Stack"]
    dnp3_interface --> dnp3_dos
    attacker["[U01] Attacker"]
    attacker --> dnp3_interface
    opc_ua_misconfig["[V03] Exploit OPC UA Misconfiguration (Anonymous Access)"]
    opc_ua_misconfig --> exploit_network_vulnerabilities
    opc_ua_server["[A03] OPC UA Server (Port 4840)"]
    opc_ua_server --> opc_ua_misconfig
    attacker["[U01] Attacker"]
    attacker --> opc_ua_server
    exploit_physical_access["[G04] Exploit Physical Access to OT Hardware"]
    exploit_physical_access --> compromise_ot_control
    firmware_tampering["[V04] Tamper with Inverter Firmware via Unsecured Ports (CVE-2021-41223)"]
    firmware_tampering --> exploit_physical_access
    inverter_usb_rs232["[A04] Inverter USB/RS-232 Ports"]
    inverter_usb_rs232 --> firmware_tampering
    attacker["[U01] Attacker"]
    attacker --> inverter_usb_rs232
    hmi_unattended["[V05] Exploit Unattended HMI Session (Weak Screen Lock)"]
    hmi_unattended --> exploit_physical_access
    hmi_workstation["[A05] Local HMI/Operator Workstation"]
    hmi_workstation --> hmi_unattended
    attacker["[U01] Attacker"]
    attacker --> hmi_workstation
    sensor_spoofing["[H01] Spoof Sensor Inputs via Physical Tampering"]
    sensor_spoofing --> exploit_physical_access
    field_sensors["[A06] Voltage/Current Sensors (CT/PT)"]
    field_sensors --> sensor_spoofing
    attacker["[U01] Attacker"]
    attacker --> field_sensors
    unsafe_actuation["[H02] Trigger Unsafe Actuator States (e.g., Relay Welder)"]
    unsafe_actuation --> sensor_spoofing
    actuators_relays["[A07] Circuit Breakers/Relays"]
    actuators_relays --> unsafe_actuation
    attacker["[U01] Attacker"]
    attacker --> actuators_relays
    supply_chain_compromise["[G05] Compromise via Supply Chain or Third-Party Access"]
    supply_chain_compromise --> compromise_ot_control
    malicious_firmware["[V06] Deploy Malicious Firmware Update (Signed but Compromised)"]
    malicious_firmware --> supply_chain_compromise
    firmware_update_mechanism["[A08] Inverter/PLC Firmware Update Channel"]
    firmware_update_mechanism --> malicious_firmware
    attacker["[U01] Attacker"]
    attacker --> firmware_update_mechanism
    vendor_backdoor["[V07] Exploit Vendor-Introduced Backdoor (e.g., Hardcoded Credentials)"]
    vendor_backdoor --> supply_chain_compromise
    plc_rtu["[A09] PLC/RTU with Default Credentials"]
    plc_rtu --> vendor_backdoor
    attacker["[U01] Attacker"]
    attacker --> plc_rtu
    disrupt_communications["[G06] Disrupt Critical Communication Flows"]
    disrupt_communications --> root
    mitm_ot_protocols["[V08] Perform MITM Attack on Serial/Ethernet OT Protocols"]
    mitm_ot_protocols --> disrupt_communications
    modbus_serial["[A10] Modbus RTU (Serial) Communication Bus"]
    modbus_serial --> mitm_ot_protocols
    attacker["[U01] Attacker"]
    attacker --> modbus_serial
    ethernet_ip["[A11] EtherNet/IP Traffic (Port 44818)"]
    ethernet_ip --> mitm_ot_protocols
    attacker["[U01] Attacker"]
    attacker --> ethernet_ip
    dos_wireless_links["[V09] DoS on Wireless Monitoring Links (Zigbee/Cellular)"]
    dos_wireless_links --> disrupt_communications
    wireless_ap["[A12] Wireless Access Point (Wi-Fi/Cellular)"]
    wireless_ap --> dos_wireless_links
    attacker["[U01] Attacker"]
    attacker --> wireless_ap
    gateway_compromise["[V10] Compromise Protocol Gateway (Modbus-to-IP Translator)"]
    gateway_compromise --> disrupt_communications
    protocol_gateway["[A13] Modbus-to-Ethernet Gateway Device"]
    protocol_gateway --> gateway_compromise
    attacker["[U01] Attacker"]
    attacker --> protocol_gateway
    spoof_plc_commands["[H03] Spoof PLC Commands via Compromised Gateway"]
    spoof_plc_commands --> gateway_compromise
    plc_control_logic["[A14] PLC Control Logic (Ladder Diagram)"]
    plc_control_logic --> spoof_plc_commands
    attacker["[U01] Attacker"]
    attacker --> plc_control_logic
    compromise_it_ot_integration["[G07] Exploit IT/OT Integration Weaknesses"]
    compromise_it_ot_integration --> root
    historian_manipulation["[V11] Manipulate Historian Data (SQL Injection in Time-Series DB)"]
    historian_manipulation --> compromise_it_ot_integration
    historian_db["[A15] Historian Database (InfluxDB/OSIsoft PI)"]
    historian_db --> historian_manipulation
    attacker["[U01] Attacker"]
    attacker --> historian_db
    cloud_api_abuse["[V12] Abuse Cloud API for Unauthorized Control (CVE-2020-25221)"]
    cloud_api_abuse --> compromise_it_ot_integration
    cloud_platform["[A16] Remote Monitoring Cloud Platform (MQTT/HTTPS)"]
    cloud_platform --> cloud_api_abuse
    attacker["[U01] Attacker"]
    attacker --> cloud_platform
    lateral_movement["[V13] Move Laterally from IT to OT via Shared Credentials"]
    lateral_movement --> compromise_it_ot_integration
    shared_ldap_creds["[A17] Shared LDAP/RADIUS Credentials (IT/OT Overlap)"]
    shared_ldap_creds --> lateral_movement
    attacker["[U01] Attacker"]
    attacker --> shared_ldap_creds
    compromise_hmi["[G08] Compromise HMI via IT Network Pivot"]
    compromise_hmi --> lateral_movement
    hmi_software_vuln["[V14] Exploit HMI Software Vulnerability (e.g., CVE-2021-34746)"]
    hmi_software_vuln --> compromise_hmi
    scada_software["[A18] SCADA/HMI Software (e.g., WinCC, Ignition)"]
    scada_software --> hmi_software_vuln
    attacker["[U01] Attacker"]
    attacker --> scada_software
    exploit_human_factors["[G09] Exploit Human Factors or Operational Weaknesses"]
    exploit_human_factors --> root
    social_engineering["[V15] Phish Operators for HMI/PLC Credentials"]
    social_engineering --> exploit_human_factors
    operator_credentials["[A19] Operator Credentials (Reused Across Systems)"]
    operator_credentials --> social_engineering
    attacker["[U01] Attacker"]
    attacker --> operator_credentials
    misconfiguration["[V16] Exploit Firewall Misconfiguration (Overly Permissive Rules)"]
    misconfiguration --> exploit_human_factors
    ot_firewall["[A20] OT Firewall (Allowing Modbus/DNP3 from IT)"]
    ot_firewall --> misconfiguration
    attacker["[U01] Attacker"]
    attacker --> ot_firewall
    lack_of_auditing["[H04] Exploit Lack of Audit Logging (Repudiation)"]
    lack_of_auditing --> exploit_human_factors
    inverter_logs["[A21] Inverter Event Logs (Tamper-Evident)"]
    inverter_logs --> lack_of_auditing
    attacker["[U01] Attacker"]
    attacker --> inverter_logs
    conceal_activities["[H05] Conceal Unauthorized Changes to MPPT/Anti-Islanding"]
    conceal_activities --> lack_of_auditing
    mppt_algorithm["[A22] MPPT Algorithm Parameters"]
    mppt_algorithm --> conceal_activities
    attacker["[U01] Attacker"]
    attacker --> mppt_algorithm
    cause_physical_damage["[G10] Cause Physical Damage or Safety Incidents"]
    cause_physical_damage --> root
    overvoltage_attack["[H06] Induce Overvoltage via Spoofed Setpoints"]
    overvoltage_attack --> cause_physical_damage
    inverter_control_logic["[A23] Inverter Voltage/Frequency Control Loop"]
    inverter_control_logic --> overvoltage_attack
    attacker["[U01] Attacker"]
    attacker --> inverter_control_logic
    grid_instability["[H07] Trigger Grid Code Violations (e.g., IEEE 1547)"]
    grid_instability --> overvoltage_attack
    grid_connection["[A24] Grid Interconnection Point"]
    grid_connection --> grid_instability
    attacker["[U01] Attacker"]
    attacker --> grid_connection
    disable_safety["[H08] Disable Safety Mechanisms (Anti-Islanding, Overcurrent)"]
    disable_safety --> cause_physical_damage
    safety_relays["[A25] Safety Relays/Circuit Breakers"]
    safety_relays --> disable_safety
    attacker["[U01] Attacker"]
    attacker --> safety_relays
    thermal_runaway["[H09] Cause Thermal Runaway via MPPT Manipulation"]
    thermal_runaway --> cause_physical_damage
    inverter_cooling["[A26] Inverter Cooling System Controls"]
    inverter_cooling --> thermal_runaway
    attacker["[U01] Attacker"]
    attacker --> inverter_cooling
    disrupt_energy_production["[G11] Disrupt Energy Production or Grid Services"]
    disrupt_energy_production --> root
    demand_response_abuse["[V17] Abuse Demand Response Signals (Unauthorized Curtailment)"]
    demand_response_abuse --> disrupt_energy_production
    demand_response_interface["[A27] Demand Response Communication Channel"]
    demand_response_interface --> demand_response_abuse
    attacker["[U01] Attacker"]
    attacker --> demand_response_interface
    fault_injection["[H10] Inject False Fault Conditions (e.g., GFDI Trip)"]
    fault_injection --> disrupt_energy_production
    fault_detection_logic["[A28] Ground Fault Detection Logic"]
    fault_detection_logic --> fault_injection
    attacker["[U01] Attacker"]
    attacker --> fault_detection_logic
    data_falsification["[H11] Falsify Energy Production Data (Financial Fraud)"]
    data_falsification --> disrupt_energy_production
    energy_metering["[A29] Energy Metering/Reporting System"]
    energy_metering --> data_falsification
    attacker["[U01] Attacker"]
    attacker --> energy_metering