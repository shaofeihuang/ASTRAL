graph BT
    root["[G01] Disrupt or Stop Cyber-Physical System Operations in Nuclear Power Plant"]
    compromise_corporate_it["[G02] Compromise Corporate IT Systems to Gain OT Access"]
    compromise_corporate_it --> root
    exploit_vpn_gateway["[V01] Exploit VPN Gateway Vulnerabilities (e.g., CVE-2019-11510)"]
    exploit_vpn_gateway --> compromise_corporate_it
    vpn_gateway["[A01] VPN Gateway (Corporate IT Perimeter)"]
    vpn_gateway --> exploit_vpn_gateway
    attacker["[U01] Attacker"]
    attacker --> vpn_gateway
    phishing_operator["[V02] Phishing Attack on Operator Workstations"]
    phishing_operator --> compromise_corporate_it
    operator_workstation_it["[A02] Operator Workstation (Corporate IT)"]
    operator_workstation_it --> phishing_operator
    attacker["[U01] Attacker"]
    attacker --> operator_workstation_it
    exploit_email_server["[V03] Exploit Email Server Zero-Day (e.g., CVE-2021-44228)"]
    exploit_email_server --> compromise_corporate_it
    email_server["[A03] Email Server (Corporate IT)"]
    email_server --> exploit_email_server
    attacker["[U01] Attacker"]
    attacker --> email_server
    compromise_dmz["[G03] Compromise DMZ to Bridge IT-OT Gap"]
    compromise_dmz --> root
    misconfigured_proxy["[V04] Misconfigured Proxy Server in DMZ"]
    misconfigured_proxy --> compromise_dmz
    proxy_server["[A04] Proxy Server (DMZ)"]
    proxy_server --> misconfigured_proxy
    attacker["[U01] Attacker"]
    attacker --> proxy_server
    opc_ua_weak_auth["[V05] Weak Authentication in OPC UA Server (e.g., Anonymous Bind)"]
    opc_ua_weak_auth --> compromise_dmz
    opc_ua_server["[A05] OPC UA Server (DMZ)"]
    opc_ua_server --> opc_ua_weak_auth
    attacker["[U01] Attacker"]
    attacker --> opc_ua_server
    unpatched_data_historian["[V06] Unpatched Data Historian (e.g., OSIsoft PI System CVE-2020-6973)"]
    unpatched_data_historian --> compromise_dmz
    data_historian["[A06] Data Historian (DMZ)"]
    data_historian --> unpatched_data_historian
    attacker["[U01] Attacker"]
    attacker --> data_historian
    compromise_scada["[G04] Compromise SCADA/DCS Systems for Process Control"]
    compromise_scada --> root
    exploit_hmi_vulnerability["[V07] Exploit HMI Software Vulnerability (e.g., Siemens WinCC CVE-2020-15782)"]
    exploit_hmi_vulnerability --> compromise_scada
    hmi_workstation["[A07] HMI Workstation (Level 3)"]
    hmi_workstation --> exploit_hmi_vulnerability
    attacker["[U01] Attacker"]
    attacker --> hmi_workstation
    modify_scada_logic["[V08] Modify SCADA Logic via Engineering Workstation"]
    modify_scada_logic --> compromise_scada
    engineering_workstation_scada["[A08] Engineering Workstation (SCADA, Level 3)"]
    engineering_workstation_scada --> modify_scada_logic
    attacker["[U01] Attacker"]
    attacker --> engineering_workstation_scada
    spoof_scada_communication["[V09] Spoof SCADA Communication (e.g., Modbus/DNP3)"]
    spoof_scada_communication --> compromise_scada
    scada_communication_link["[A09] SCADA Communication Link (Level 3 ↔ Level 2)"]
    scada_communication_link --> spoof_scada_communication
    attacker["[U01] Attacker"]
    attacker --> scada_communication_link
    compromise_dcs_plc["[G05] Compromise DCS/PLC for Direct Process Manipulation"]
    compromise_dcs_plc --> root
    exploit_plc_firmware["[V10] Exploit PLC Firmware Vulnerability (e.g., Schneider Modicon CVE-2019-10956)"]
    exploit_plc_firmware --> compromise_dcs_plc
    plc_firmware["[A10] PLC Firmware (Level 1)"]
    plc_firmware --> exploit_plc_firmware
    attacker["[U01] Attacker"]
    attacker --> plc_firmware
    tamper_plc_ladder_logic["[V11] Tamper with PLC Ladder Logic via Engineering Workstation"]
    tamper_plc_ladder_logic --> compromise_dcs_plc
    engineering_workstation_plc["[A11] Engineering Workstation (PLC, Level 2)"]
    engineering_workstation_plc --> tamper_plc_ladder_logic
    attacker["[U01] Attacker"]
    attacker --> engineering_workstation_plc
    disable_sis_interlocks["[V12] Disable Safety Instrumented System (SIS) Interlocks"]
    disable_sis_interlocks --> compromise_dcs_plc
    sis_plc["[A12] SIS PLC (Level 1, Safety Zone)"]
    sis_plc --> disable_sis_interlocks
    attacker["[U01] Attacker"]
    attacker --> sis_plc
    compromise_field_devices["[G06] Compromise Field Devices for Sensor/Actuator Manipulation"]
    compromise_field_devices --> root
    spoof_sensor_data["[V13] Spoof Sensor Data (e.g., Temperature/Pressure Readings)"]
    spoof_sensor_data --> compromise_field_devices
    field_sensor["[A13] Field Sensor (Level 0)"]
    field_sensor --> spoof_sensor_data
    attacker["[U01] Attacker"]
    attacker --> field_sensor
    manipulate_actuator["[V14] Manipulate Actuator (e.g., Valve/Pump Control)"]
    manipulate_actuator --> compromise_field_devices
    field_actuator["[A14] Field Actuator (Level 0)"]
    field_actuator --> manipulate_actuator
    attacker["[U01] Attacker"]
    attacker --> field_actuator
    exploit_wireless_io["[V15] Exploit Wireless I/O Network Vulnerabilities"]
    exploit_wireless_io --> compromise_field_devices
    wireless_io_network["[A15] Wireless I/O Network (Level 0 ↔ Level 1)"]
    wireless_io_network --> exploit_wireless_io
    attacker["[U01] Attacker"]
    attacker --> wireless_io_network
    compromise_remote_access["[G07] Compromise Remote Access for External Control"]
    compromise_remote_access --> root
    exploit_vendor_portal["[V16] Exploit Vendor Remote Access Portal (e.g., Siemens TIA Portal)"]
    exploit_vendor_portal --> compromise_remote_access
    vendor_remote_portal["[A16] Vendor Remote Access Portal (DMZ/Level 3)"]
    vendor_remote_portal --> exploit_vendor_portal
    attacker["[U01] Attacker"]
    attacker --> vendor_remote_portal
    compromise_vpn_credentials["[V17] Compromise VPN Credentials via Social Engineering"]
    compromise_vpn_credentials --> compromise_remote_access
    vpn_credentials["[A17] VPN Credentials (Corporate IT/OT)"]
    vpn_credentials --> compromise_vpn_credentials
    attacker["[U01] Attacker"]
    attacker --> vpn_credentials
    exploit_rdp_vulnerability["[V18] Exploit RDP Vulnerability (e.g., BlueKeep CVE-2019-0708)"]
    exploit_rdp_vulnerability --> compromise_remote_access
    rdp_server["[A18] RDP Server (DMZ/Level 3)"]
    rdp_server --> exploit_rdp_vulnerability
    attacker["[U01] Attacker"]
    attacker --> rdp_server
    compromise_physical_security["[G08] Compromise Physical Security for Direct Access"]
    compromise_physical_security --> root
    bypass_access_control["[V19] Bypass Physical Access Control (e.g., Tailgating)"]
    bypass_access_control --> compromise_physical_security
    physical_access_system["[A19] Physical Access Control System (Level 0-3)"]
    physical_access_system --> bypass_access_control
    attacker["[U01] Attacker"]
    attacker --> physical_access_system
    exploit_usb_drive["[V20] Exploit USB Drive for Malware Introduction"]
    exploit_usb_drive --> compromise_physical_security
    engineering_workstation_usb["[A20] Engineering Workstation with USB Port (Level 2/3)"]
    engineering_workstation_usb --> exploit_usb_drive
    attacker["[U01] Attacker"]
    attacker --> engineering_workstation_usb
    tamper_field_device["[V21] Tamper with Field Device via Direct Physical Access"]
    tamper_field_device --> compromise_physical_security
    field_device_physical["[A21] Field Device (Level 0, Physical Access)"]
    field_device_physical --> tamper_field_device
    attacker["[U01] Attacker"]
    attacker --> field_device_physical
    exploit_supply_chain["[G09] Exploit Supply Chain for Persistent Compromise"]
    exploit_supply_chain --> root
    compromise_vendor_software["[V22] Compromise Vendor-Supplied Software (e.g., DCS Patch)"]
    compromise_vendor_software --> exploit_supply_chain
    vendor_software_update["[A22] Vendor Software Update (Supply Chain)"]
    vendor_software_update --> compromise_vendor_software
    attacker["[U01] Attacker"]
    attacker --> vendor_software_update
    hardware_trojan_plc["[V23] Introduce Hardware Trojan in PLC/IED"]
    hardware_trojan_plc --> exploit_supply_chain
    plc_hardware["[A23] PLC/IED Hardware (Supply Chain)"]
    plc_hardware --> hardware_trojan_plc
    attacker["[U01] Attacker"]
    attacker --> plc_hardware
    compromise_third_party_maintenance["[V24] Compromise Third-Party Maintenance Credentials"]
    compromise_third_party_maintenance --> exploit_supply_chain
    third_party_credentials["[A24] Third-Party Maintenance Credentials (Supply Chain)"]
    third_party_credentials --> compromise_third_party_maintenance
    attacker["[U01] Attacker"]
    attacker --> third_party_credentials
    exploit_human_factor["[G10] Exploit Human Factors for Insider Threats"]
    exploit_human_factor --> root
    social_engineer_operator["[V25] Social Engineer Operator to Execute Malicious Actions"]
    social_engineer_operator --> exploit_human_factor
    operator_hmi["[A25] Operator HMI Console (Level 3)"]
    operator_hmi --> social_engineer_operator
    attacker["[U01] Attacker"]
    attacker --> operator_hmi
    misuse_privileged_access["[V26] Misuse Privileged Access (e.g., Engineer with Admin Rights)"]
    misuse_privileged_access --> exploit_human_factor
    privileged_engineer_access["[A26] Privileged Engineer Access (Level 2/3)"]
    privileged_engineer_access --> misuse_privileged_access
    attacker["[U01] Attacker"]
    attacker --> privileged_engineer_access
    bypass_safety_procedures["[V27] Bypass Safety Procedures via Human Error"]
    bypass_safety_procedures --> exploit_human_factor
    safety_procedure_bypass["[A27] Safety Procedure Bypass (Human Factor)"]
    safety_procedure_bypass --> bypass_safety_procedures
    attacker["[U01] Attacker"]
    attacker --> safety_procedure_bypass
    disrupt_network_infra["[G11] Disrupt Network Infrastructure for Communication Failure"]
    disrupt_network_infra --> root
    dos_industrial_switch["[V28] DoS Attack on Industrial Switch (e.g., Cisco CVE-2019-18218)"]
    dos_industrial_switch --> disrupt_network_infra
    industrial_switch["[A28] Industrial Network Switch (Level 1-3)"]
    industrial_switch --> dos_industrial_switch
    attacker["[U01] Attacker"]
    attacker --> industrial_switch
    exploit_router_vulnerability["[V29] Exploit Router Vulnerability for Traffic Redirection"]
    exploit_router_vulnerability --> disrupt_network_infra
    industrial_router["[A29] Industrial Router (Level 2/3)"]
    industrial_router --> exploit_router_vulnerability
    attacker["[U01] Attacker"]
    attacker --> industrial_router
    jamming_wireless_communication["[V30] Jam Wireless Communication (e.g., WirelessHART)"]
    jamming_wireless_communication --> disrupt_network_infra
    wireless_communication["[A30] Wireless Communication Link (Level 0 ↔ Level 1)"]
    wireless_communication --> jamming_wireless_communication
    attacker["[U01] Attacker"]
    attacker --> wireless_communication
    manipulate_safety_systems["[G12] Manipulate Safety Systems for Catastrophic Failure"]
    manipulate_safety_systems --> root
    disable_emergency_shutdown["[V31] Disable Emergency Shutdown Mechanisms (e.g., Reactor Trip System)"]
    disable_emergency_shutdown --> manipulate_safety_systems
    emergency_shutdown_system["[A31] Emergency Shutdown System (SIS, Level 1)"]
    emergency_shutdown_system --> disable_emergency_shutdown
    attacker["[U01] Attacker"]
    attacker --> emergency_shutdown_system
    tamper_radiation_monitors["[V32] Tamper with Radiation Monitors to Mask Leaks"]
    tamper_radiation_monitors --> manipulate_safety_systems
    radiation_monitor["[A32] Radiation Monitoring System (Level 0/1)"]
    radiation_monitor --> tamper_radiation_monitors
    attacker["[U01] Attacker"]
    attacker --> radiation_monitor
    compromise_diesel_generators["[V33] Compromise Emergency Diesel Generators (EDG)"]
    compromise_diesel_generators --> manipulate_safety_systems
    emergency_diesel_generator["[A33] Emergency Diesel Generator Controller (Level 1)"]
    emergency_diesel_generator --> compromise_diesel_generators
    attacker["[U01] Attacker"]
    attacker --> emergency_diesel_generator
    exploit_protocol_weaknesses["[G13] Exploit Industrial Protocol Weaknesses"]
    exploit_protocol_weaknesses --> root
    modbus_unauthenticated_write["[V34] Exploit Modbus Unauthenticated Write (FC5/6)"]
    modbus_unauthenticated_write --> exploit_protocol_weaknesses
    modbus_communication["[A34] Modbus Communication Link (Level 1 ↔ Level 2)"]
    modbus_communication --> modbus_unauthenticated_write
    attacker["[U01] Attacker"]
    attacker --> modbus_communication
    dnp3_replay_attack["[V35] DNP3 Replay Attack for Command Spoofing"]
    dnp3_replay_attack --> exploit_protocol_weaknesses
    dnp3_communication["[A35] DNP3 Communication Link (Level 1 ↔ Level 2)"]
    dnp3_communication --> dnp3_replay_attack
    attacker["[U01] Attacker"]
    attacker --> dnp3_communication
    opc_ua_weak_encryption["[V36] Exploit OPC UA Weak Encryption/Certificate Validation"]
    opc_ua_weak_encryption --> exploit_protocol_weaknesses
    opc_ua_communication["[A36] OPC UA Communication Link (DMZ ↔ Level 3)"]
    opc_ua_communication --> opc_ua_weak_encryption
    attacker["[U01] Attacker"]
    attacker --> opc_ua_communication
    persistent_compromise["[G14] Achieve Persistent Compromise in OT Environment"]
    persistent_compromise --> root
    install_malware_plc["[V37] Install Malware on PLC (e.g., Stuxnet-like Rootkit)"]
    install_malware_plc --> persistent_compromise
    plc_malware["[A37] PLC with Malware (Level 1)"]
    plc_malware --> install_malware_plc
    attacker["[U01] Attacker"]
    attacker --> plc_malware
    backdoor_engineering_workstation["[V38] Backdoor Engineering Workstation for Future Access"]
    backdoor_engineering_workstation --> persistent_compromise
    engineering_workstation_backdoor["[A38] Backdoored Engineering Workstation (Level 2/3)"]
    engineering_workstation_backdoor --> backdoor_engineering_workstation
    attacker["[U01] Attacker"]
    attacker --> engineering_workstation_backdoor
    compromise_firmware_update["[V39] Compromise Firmware Update Mechanism"]
    compromise_firmware_update --> persistent_compromise
    firmware_update_mechanism["[A39] Firmware Update Server (Level 3)"]
    firmware_update_mechanism --> compromise_firmware_update
    attacker["[U01] Attacker"]
    attacker --> firmware_update_mechanism
    cause_physical_damage["[G15] Cause Physical Damage to Critical Infrastructure"]
    cause_physical_damage --> root
    overheat_reactor_core["[H01] Overheat Reactor Core via Coolant Pump Manipulation"]
    overheat_reactor_core --> cause_physical_damage
    coolant_pump_controller["[A40] Coolant Pump Controller (Level 1)"]
    coolant_pump_controller --> overheat_reactor_core
    attacker["[U01] Attacker"]
    attacker --> coolant_pump_controller
    damage_turbine["[H02] Damage Turbine via Erratic Steam Flow Control"]
    damage_turbine --> cause_physical_damage
    turbine_control_system["[A41] Turbine Control System (Level 1/2)"]
    turbine_control_system --> damage_turbine
    attacker["[U01] Attacker"]
    attacker --> turbine_control_system
    disrupt_grid_synchronization["[H03] Disrupt Grid Synchronization via IED Manipulation"]
    disrupt_grid_synchronization --> cause_physical_damage
    grid_interface_ieds["[A42] Grid Interface IEDs (Level 0/1)"]
    grid_interface_ieds --> disrupt_grid_synchronization
    attacker["[U01] Attacker"]
    attacker --> grid_interface_ieds
    cause_steam_explosion["[H04] Cause Steam Explosion via Pressure Valve Tampering"]
    cause_steam_explosion --> cause_physical_damage
    pressure_valve_controller["[A43] Pressure Valve Controller (Level 1)"]
    pressure_valve_controller --> cause_steam_explosion
    attacker["[U01] Attacker"]
    attacker --> pressure_valve_controller
    disable_containment_systems["[H05] Disable Containment Systems for Radiation Leak"]
    disable_containment_systems --> cause_physical_damage
    containment_system_controller["[A44] Containment System Controller (Level 1, Safety Zone)"]
    containment_system_controller --> disable_containment_systems
    attacker["[U01] Attacker"]
    attacker --> containment_system_controller
    cause_operational_disruption["[G16] Cause Prolonged Operational Disruption"]
    cause_operational_disruption --> root
    disable_hvac_control["[H06] Disable HVAC Control for Equipment Overheating"]
    disable_hvac_control --> cause_operational_disruption
    hvac_control_system["[A45] HVAC Control System (Level 2)"]
    hvac_control_system --> disable_hvac_control
    attacker["[U01] Attacker"]
    attacker --> hvac_control_system
    corrupt_data_historian["[H07] Corrupt Data Historian for False Process Trends"]
    corrupt_data_historian --> cause_operational_disruption
    data_historian_corruption["[A46] Data Historian (Level 3/4)"]
    data_historian_corruption --> corrupt_data_historian
    attacker["[U01] Attacker"]
    attacker --> data_historian_corruption
    disrupt_fuel_handling["[H08] Disrupt Fuel Handling Systems for Outage Extension"]
    disrupt_fuel_handling --> cause_operational_disruption
    fuel_handling_system["[A47] Fuel Handling System Controller (Level 1)"]
    fuel_handling_system --> disrupt_fuel_handling
    attacker["[U01] Attacker"]
    attacker --> fuel_handling_system