graph BT
    root["[G01] Disrupt or Stop Cyber-Physical System Operations (Heating System)"]
    spoof_goal["[G02] Spoof Legitimate Commands or Data"]
    spoof_goal --> root
    bms_protocol["[A01] Building Management System (BMS) Protocols (Modbus, BACnet, OPC UA)"]
    bms_protocol --> spoof_goal
    weak_auth_bms["[V01] Weak or Missing Authentication in BMS Protocols"]
    weak_auth_bms --> bms_protocol
    modbus_no_auth["[V02] Modbus TCP/RTU Lacking Authentication (Default Configuration)"]
    modbus_no_auth --> weak_auth_bms
    attacker["[U01] Attacker"]
    attacker --> modbus_no_auth
    bacnet_broadcast["[V03] BACnet Broadcast Messages Vulnerable to Spoofing (Who-Is, I-Am)"]
    bacnet_broadcast --> weak_auth_bms
    attacker["[U01] Attacker"]
    attacker --> bacnet_broadcast
    opc_ua_misconfig["[V04] OPC UA Misconfigured Certificates or Disabled Encryption"]
    opc_ua_misconfig --> weak_auth_bms
    attacker["[U01] Attacker"]
    attacker --> opc_ua_misconfig
    cve_2022_3028["[V05] Exploit CVE-2022-3028 (BMS Protocol Vulnerability)"]
    cve_2022_3028 --> bms_protocol
    attacker["[U01] Attacker"]
    attacker --> cve_2022_3028
    spoofed_sensor_data["[H01] Spoofed Sensor Data (Temperature, Pressure, Flow)"]
    spoofed_sensor_data --> spoof_goal
    false_low_temp["[H02] False Low-Temperature Readings Causing Overcompensation (Overheating Risk)"]
    false_low_temp --> spoofed_sensor_data
    attacker["[U01] Attacker"]
    attacker --> false_low_temp
    false_high_temp["[H03] False High-Temperature Readings Causing System Shutdown (DoS)"]
    false_high_temp --> spoofed_sensor_data
    attacker["[U01] Attacker"]
    attacker --> false_high_temp
    spoofed_control["[H04] Spoofed Control Commands (Direct Actuator Manipulation)"]
    spoofed_control --> spoof_goal
    unauth_modbus_cmd["[H05] Unauthorized Modbus Commands to Actuators (e.g., Open Valve 100%)"]
    unauth_modbus_cmd --> spoofed_control
    attacker["[U01] Attacker"]
    attacker --> unauth_modbus_cmd
    tamper_goal["[G03] Tamper with Control Logic or System Configurations"]
    tamper_goal --> root
    eng_workstation["[A02] Engineering Workstation (PLC Programming, HMI Configuration)"]
    eng_workstation --> tamper_goal
    weak_access_control["[V06] Weak Access Controls on Engineering Workstations (Default/Shared Credentials)"]
    weak_access_control --> eng_workstation
    attacker["[U01] Attacker"]
    attacker --> weak_access_control
    cve_2021_22893["[V07] Exploit CVE-2021-22893 (Control Logic Vulnerability)"]
    cve_2021_22893 --> eng_workstation
    attacker["[U01] Attacker"]
    attacker --> cve_2021_22893
    plc_firmware["[A03] PLC Firmware/Logic (Ladder Logic, Control Algorithms)"]
    plc_firmware --> tamper_goal
    unauth_firmware_update["[V08] Unauthenticated Firmware Update Mechanism"]
    unauth_firmware_update --> plc_firmware
    malicious_firmware["[H06] Injection of Malicious Firmware (Altered Control Loops)"]
    malicious_firmware --> unauth_firmware_update
    attacker["[U01] Attacker"]
    attacker --> malicious_firmware
    logic_bomb["[H07] Logic Bomb in PLC Code (Time/Delay-Based Trigger)"]
    logic_bomb --> plc_firmware
    attacker["[U01] Attacker"]
    attacker --> logic_bomb
    safety_interlocks["[A04] Safety Instrumented Systems (SIS) or Interlocks"]
    safety_interlocks --> tamper_goal
    bypass_interlocks["[H08] Bypass or Disable Safety Interlocks (Max Temperature Limits)"]
    bypass_interlocks --> safety_interlocks
    attacker["[U01] Attacker"]
    attacker --> bypass_interlocks
    tamper_impact["[H09] Tampering-Induced Physical Hazards"]
    tamper_impact --> tamper_goal
    overheat_equipment["[H10] Overheating of Critical Components (Boiler, Heat Exchanger)"]
    overheat_equipment --> tamper_impact
    attacker["[U01] Attacker"]
    attacker --> overheat_equipment
    erratic_actuation["[H11] Erratic Actuator Behavior (Rapid Cycling of Valves/Dampers)"]
    erratic_actuation --> tamper_impact
    attacker["[U01] Attacker"]
    attacker --> erratic_actuation
    repudiation_goal["[G04] Compromise Logging or Audit Mechanisms (Repudiation)"]
    repudiation_goal --> root
    scada_logs["[A05] SCADA/HMI Audit Logs (Operator Actions, System Events)"]
    scada_logs --> repudiation_goal
    log_tampering["[V09] Insecure Log Storage (Unencrypted, Writable by Low-Privilege Users)"]
    log_tampering --> scada_logs
    delete_logs["[H12] Deletion of Critical Logs (Covering Tracks)"]
    delete_logs --> log_tampering
    attacker["[U01] Attacker"]
    attacker --> delete_logs
    inject_false_logs["[H13] Injection of False Log Entries (Misleading Forensics)"]
    inject_false_logs --> log_tampering
    attacker["[U01] Attacker"]
    attacker --> inject_false_logs
    historian_data["[A06] Historian Database (Time-Series Operational Data)"]
    historian_data --> repudiation_goal
    historian_access["[V10] Excessive Permissions on Historian (Read/Write for Non-Admin Users)"]
    historian_access --> historian_data
    alter_trends["[H14] Alter Historical Trends (Hide Equipment Degradation)"]
    alter_trends --> historian_access
    attacker["[U01] Attacker"]
    attacker --> alter_trends
    repudiation_impact["[H15] Lack of Accountability for Malicious Actions"]
    repudiation_impact --> repudiation_goal
    undetected_activities["[H16] Prolonged Undetected Malicious Activities (Persistent Compromise)"]
    undetected_activities --> repudiation_impact
    attacker["[U01] Attacker"]
    attacker --> undetected_activities
    info_disclosure_goal["[G05] Unauthorized Information Disclosure"]
    info_disclosure_goal --> root
    web_interface["[A07] Heating System Web Interface (Configuration, Monitoring)"]
    web_interface --> info_disclosure_goal
    cve_2020_25223["[V11] Exploit CVE-2020-25223 (Web Interface Vulnerability)"]
    cve_2020_25223 --> web_interface
    attacker["[U01] Attacker"]
    attacker --> cve_2020_25223
    default_creds["[V12] Default or Weak Credentials on Web Interface"]
    default_creds --> web_interface
    attacker["[U01] Attacker"]
    attacker --> default_creds
    exposed_data["[H17] Exposure of Sensitive Operational Data"]
    exposed_data --> info_disclosure_goal
    leak_configs["[H18] Leak of System Configurations (PLC Logic, Network Topology)"]
    leak_configs --> exposed_data
    attacker["[U01] Attacker"]
    attacker --> leak_configs
    leak_creds["[H19] Leak of User Credentials (Reuse in Lateral Movement)"]
    leak_creds --> exposed_data
    attacker["[U01] Attacker"]
    attacker --> leak_creds
    enterprise_integration["[A08] Enterprise Integration Points (APIs, Gateways)"]
    enterprise_integration --> info_disclosure_goal
    insecure_api["[V13] Insecure API Endpoints (Lack of Rate Limiting, Authentication)"]
    insecure_api --> enterprise_integration
    data_exfil["[H20] Exfiltration of Operational Data to External Servers"]
    data_exfil --> insecure_api
    attacker["[U01] Attacker"]
    attacker --> data_exfil
    dos_goal["[G06] Denial of Service (DoS) on Critical Components"]
    dos_goal --> root
    network_infra["[A09] Network Infrastructure (Switches, Routers, Firewalls)"]
    network_infra --> dos_goal
    cve_2019_18218["[V14] Exploit CVE-2019-18218 (Network Protocol Vulnerability)"]
    cve_2019_18218 --> network_infra
    attacker["[U01] Attacker"]
    attacker --> cve_2019_18218
    flood_traffic["[H21] Traffic Flooding (Modbus TCP, OPC UA Ports)"]
    flood_traffic --> network_infra
    attacker["[U01] Attacker"]
    attacker --> flood_traffic
    plc_comms["[A10] PLC Communication Channels (Cyclic Polling, Heartbeats)"]
    plc_comms --> dos_goal
    disrupt_heartbeat["[H22] Disrupt PLC Heartbeat Messages (Cause Fail-Safe Shutdown)"]
    disrupt_heartbeat --> plc_comms
    attacker["[U01] Attacker"]
    attacker --> disrupt_heartbeat
    hmi_servers["[A11] HMI/SCADA Servers (Operator Interfaces)"]
    hmi_servers --> dos_goal
    resource_exhaustion["[H23] Resource Exhaustion (CPU/Memory) via Malformed Packets"]
    resource_exhaustion --> hmi_servers
    attacker["[U01] Attacker"]
    attacker --> resource_exhaustion
    dos_impact["[H24] DoS-Induced Operational Disruption"]
    dos_impact --> dos_goal
    loss_of_control["[H25] Loss of Heating Control (Freezing Risk in Critical Areas)"]
    loss_of_control --> dos_impact
    attacker["[U01] Attacker"]
    attacker --> loss_of_control
    system_reboot["[H26] Forced System Reboots (Disrupting Processes)"]
    system_reboot --> dos_impact
    attacker["[U01] Attacker"]
    attacker --> system_reboot
    priv_esc_goal["[G07] Elevation of Privilege (Unauthorized Admin Access)"]
    priv_esc_goal --> root
    access_control["[A12] Access Control Mechanisms (RBAC, Local Accounts)"]
    access_control --> priv_esc_goal
    cve_2021_34527["[V15] Exploit CVE-2021-34527 (Privilege Escalation Vulnerability)"]
    cve_2021_34527 --> access_control
    attacker["[U01] Attacker"]
    attacker --> cve_2021_34527
    cred_theft["[V16] Theft of Credentials (Keylogging, Pass-the-Hash)"]
    cred_theft --> access_control
    attacker["[U01] Attacker"]
    attacker --> cred_theft
    remote_access["[A13] Remote Access Portals (VPN, Jump Hosts)"]
    remote_access --> priv_esc_goal
    vpn_misconfig["[V17] Misconfigured VPN (Weak Encryption, No MFA)"]
    vpn_misconfig --> remote_access
    attacker["[U01] Attacker"]
    attacker --> vpn_misconfig
    priv_esc_impact["[H27] Abuse of Elevated Privileges"]
    priv_esc_impact --> priv_esc_goal
    unauth_shutdown["[H28] Unauthorized System Shutdown or Reconfiguration"]
    unauth_shutdown --> priv_esc_impact
    attacker["[U01] Attacker"]
    attacker --> unauth_shutdown
    persist_access["[H29] Persistent Backdoor Installation (Maintain Long-Term Access)"]
    persist_access --> priv_esc_impact
    attacker["[U01] Attacker"]
    attacker --> persist_access
    lateral_movement_goal["[G08] Lateral Movement Across System Components"]
    lateral_movement_goal --> root
    network_segmentation["[A14] Network Segmentation (VLANs, Firewalls)"]
    network_segmentation --> lateral_movement_goal
    flat_network["[V18] Flat Network Architecture (No Segmentation Between OT Levels)"]
    flat_network --> network_segmentation
    attacker["[U01] Attacker"]
    attacker --> flat_network
    weak_acls["[V19] Weak ACLs on Industrial Switches (Allow Unrestricted Traffic)"]
    weak_acls --> network_segmentation
    attacker["[U01] Attacker"]
    attacker --> weak_acls
    compromised_device["[A15] Compromised Field Device (Sensor, Actuator, RTU)"]
    compromised_device --> lateral_movement_goal
    default_device_creds["[V20] Default Credentials on Field Devices (Modbus, BACnet Devices)"]
    default_device_creds --> compromised_device
    pivot_to_plc["[H30] Pivot from Compromised Sensor to PLC (Modbus Master)"]
    pivot_to_plc --> default_device_creds
    attacker["[U01] Attacker"]
    attacker --> pivot_to_plc
    engineering_ws["[A16] Engineering Workstation (Shared Across Multiple Systems)"]
    engineering_ws --> lateral_movement_goal
    shared_creds["[V21] Shared Credentials Across Multiple OT Systems"]
    shared_creds --> engineering_ws
    lateral_to_scada["[H31] Lateral Movement from Engineering WS to SCADA Server"]
    lateral_to_scada --> shared_creds
    attacker["[U01] Attacker"]
    attacker --> lateral_to_scada
    lateral_impact["[H32] Widespread System Compromise via Lateral Movement"]
    lateral_impact --> lateral_movement_goal
    full_system_control["[H33] Gain Control of Entire Heating System (PLCs, HMIs, Historians)"]
    full_system_control --> lateral_impact
    attacker["[U01] Attacker"]
    attacker --> full_system_control
    physical_goal["[G09] Physical Tampering or Access"]
    physical_goal --> root
    local_hmi["[A17] Local HMI Panels (Unsecured Physical Access)"]
    local_hmi --> physical_goal
    unlocked_hmi["[V22] Unlocked or Default-Pinned HMI Panels"]
    unlocked_hmi --> local_hmi
    attacker["[U01] Attacker"]
    attacker --> unlocked_hmi
    field_devices["[A18] Field Devices (Sensors, Actuators, Valves)"]
    field_devices --> physical_goal
    physical_tamper["[H34] Physical Tampering with Sensors/Actuators (Replacement, Signal Jamming)"]
    physical_tamper --> field_devices
    attacker["[U01] Attacker"]
    attacker --> physical_tamper
    usb_ports["[A19] USB Ports on Engineering Workstations/PLCs"]
    usb_ports --> physical_goal
    unrestricted_usb["[V23] Unrestricted USB Access (No Disabling or Whitelisting)"]
    unrestricted_usb --> usb_ports
    malware_via_usb["[H35] Introduction of Malware via USB (e.g., Stuxnet-like Payload)"]
    malware_via_usb --> unrestricted_usb
    attacker["[U01] Attacker"]
    attacker --> malware_via_usb
    supply_chain["[A20] Supply Chain (Third-Party Vendors, Firmware Updates)"]
    supply_chain --> physical_goal
    compromised_updates["[V24] Compromised Firmware or Patch Updates"]
    compromised_updates --> supply_chain
    attacker["[U01] Attacker"]
    attacker --> compromised_updates
    rogue_vendor["[H36] Rogue Vendor Access (Abuse of Remote Support Tools)"]
    rogue_vendor --> supply_chain
    attacker["[U01] Attacker"]
    attacker --> rogue_vendor