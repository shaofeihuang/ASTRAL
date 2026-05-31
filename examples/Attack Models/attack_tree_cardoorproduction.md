graph BT
    root["[G01] CPS Disruption: Compromise of Automotive Door Assembly Line Operations"]
    spoofing_goal["[G02] Achieve Spoofing-Based Disruption"]
    spoofing_goal --> root
    plc_spoofing["[A01] PLC (Programmable Logic Controller) Robotic Arm Command Interface"]
    plc_spoofing --> spoofing_goal
    plc_auth_weakness["[V01] Weak Authentication in PLC (Default Credentials/No MFA)"]
    plc_auth_weakness --> plc_spoofing
    spoofed_weld_commands["[H01] Spoofed Welding Commands Leading to Structural Weakness"]
    spoofed_weld_commands --> plc_auth_weakness
    attacker["[U01] Attacker"]
    attacker --> spoofed_weld_commands
    hmi_spoofing["[A02] HMI (Human-Machine Interface) Operator Workstation"]
    hmi_spoofing --> spoofing_goal
    hmi_ip_spoofing["[V02] IP Spoofing Vulnerability in HMI Session Management"]
    hmi_ip_spoofing --> hmi_spoofing
    conveyor_speed_manipulation["[H02] Unsafe Conveyor Speed Commands Causing Worker Injuries"]
    conveyor_speed_manipulation --> hmi_ip_spoofing
    attacker --> conveyor_speed_manipulation
    tampering_goal["[G03] Achieve Tampering-Based Disruption"]
    tampering_goal --> root
    scada_tampering["[A03] SCADA System Configuration Interface"]
    scada_tampering --> tampering_goal
    scada_cve_2017_5164["[V03] CVE-2017-5164 (Siemens SCADA Vulnerability)"]
    scada_cve_2017_5164 --> scada_tampering
    press_force_misconfig["[H03] Excessive Hydraulic Press Force Damaging Door Panels"]
    press_force_misconfig --> scada_cve_2017_5164
    attacker --> press_force_misconfig
    mes_tampering["[A04] MES (Manufacturing Execution System) Production Scheduler"]
    mes_tampering --> tampering_goal
    mes_schedule_vuln["[V04] Insecure Direct Object Reference in MES Scheduling API"]
    mes_schedule_vuln --> mes_tampering
    production_delay_cascade["[H04] Cascading Production Delays from Schedule Tampering"]
    production_delay_cascade --> mes_schedule_vuln
    attacker --> production_delay_cascade
    repudiation_goal["[G04] Achieve Repudiation-Based Disruption"]
    repudiation_goal --> root
    plc_logging["[A05] PLC Audit Logging System"]
    plc_logging --> repudiation_goal
    plc_logging_insufficient["[V05] Insufficient Logging of Critical Parameter Changes"]
    plc_logging_insufficient --> plc_logging
    paint_mixing_untraceable["[H05] Untraceable Paint Mixing Ratio Alterations Causing Defects"]
    paint_mixing_untraceable --> plc_logging_insufficient
    attacker --> paint_mixing_untraceable
    info_disclosure_goal["[G05] Achieve Information Disclosure-Based Disruption"]
    info_disclosure_goal --> root
    hmi_data_leak["[A06] HMI Proprietary Process Data Storage"]
    hmi_data_leak --> info_disclosure_goal
    hmi_cve_2018_4834["[V06] CVE-2018-4834 (Rockwell HMI Information Disclosure)"]
    hmi_cve_2018_4834 --> hmi_data_leak
    process_secrets_theft["[H06] Theft of Proprietary Assembly Process Intellectual Property"]
    process_secrets_theft --> hmi_cve_2018_4834
    attacker --> process_secrets_theft
    mes_employee_data["[A07] MES Employee Records Database"]
    mes_employee_data --> info_disclosure_goal
    mes_db_misconfig["[V07] Misconfigured Database Permissions Allowing Unauthorized Access"]
    mes_db_misconfig --> mes_employee_data
    employee_privacy_violation["[H07] Unauthorized Disclosure of Sensitive Employee Information"]
    employee_privacy_violation --> mes_db_misconfig
    attacker --> employee_privacy_violation
    dos_goal["[G06] Achieve Denial-of-Service-Based Disruption"]
    dos_goal --> root
    scada_dos["[A08] SCADA System Core Services"]
    scada_dos --> dos_goal
    scada_protocol_flood["[V08] Unprotected OPC UA Classic Ports Susceptible to Flooding"]
    scada_protocol_flood --> scada_dos
    scada_system_crash["[H08] SCADA System Crash Halting Production Line"]
    scada_system_crash --> scada_protocol_flood
    attacker --> scada_system_crash
    network_dos["[A09] OT Network Infrastructure (Switches/Routers)"]
    network_dos --> dos_goal
    network_flood_vuln["[V09] Lack of Storm Control on Industrial Switches"]
    network_flood_vuln --> network_dos
    network_outage_coordination_loss["[H09] Complete Loss of Component Coordination from Network Outage"]
    network_outage_coordination_loss --> network_flood_vuln
    attacker --> network_outage_coordination_loss
    priv_escalation_goal["[G07] Achieve Privilege Escalation-Based Disruption"]
    priv_escalation_goal --> root
    plc_priv_esc["[A10] PLC Administrative Access Control"]
    plc_priv_esc --> priv_escalation_goal
    plc_cve_2019_10975["[V10] CVE-2019-10975 (Schneider Electric PLC Privilege Escalation)"]
    plc_cve_2019_10975 --> plc_priv_esc
    plc_critical_process_manipulation["[H10] Unauthorized Critical Process Manipulation via Elevated PLC Access"]
    plc_critical_process_manipulation --> plc_cve_2019_10975
    attacker --> plc_critical_process_manipulation
    lateral_movement_goal["[G08] Achieve Lateral Movement-Based Disruption"]
    lateral_movement_goal --> root
    it_ot_boundary["[A11] IT-OT Boundary Firewall/Router"]
    it_ot_boundary --> lateral_movement_goal
    boundary_misconfig["[V11] Firewall Misconfiguration Allowing Unrestricted IT→OT Traffic"]
    boundary_misconfig --> it_ot_boundary
    ot_system_compromise_via_it["[H11] OT System Compromise Originating from IT Network"]
    ot_system_compromise_via_it --> boundary_misconfig
    attacker --> ot_system_compromise_via_it
    weak_segmentation["[A12] Flat OT Network Architecture"]
    weak_segmentation --> lateral_movement_goal
    no_microsegmentation["[V12] Lack of Microsegmentation Between Purdue Levels 2-3"]
    no_microsegmentation --> weak_segmentation
    mes_to_plc_unauthorized_access["[H12] Unauthorized MES→PLC Command Injection via Lateral Movement"]
    mes_to_plc_unauthorized_access --> no_microsegmentation
    attacker --> mes_to_plc_unauthorized_access
    supply_chain_goal["[G09] Achieve Supply Chain-Based Disruption"]
    supply_chain_goal --> root
    third_party_software["[A13] Vendor-Supplied PLC Firmware/OPC UA Stack"]
    third_party_software --> supply_chain_goal
    known_cve_in_firmware["[V13] Known Unpatched CVE in Vendor-Supplied Firmware"]
    known_cve_in_firmware --> third_party_software
    malicious_firmware_update["[H13] Compromised Firmware Update Introducing Backdoor"]
    malicious_firmware_update --> known_cve_in_firmware
    attacker --> malicious_firmware_update
    supplier_access["[A14] Supplier Remote Maintenance VPN Portal"]
    supplier_access --> supply_chain_goal
    default_supplier_credentials["[V14] Default/Weak Credentials on Supplier VPN Accounts"]
    default_supplier_credentials --> supplier_access
    supplier_credential_abuse["[H14] Abuse of Supplier Credentials for Unauthorized PLC Access"]
    supplier_credential_abuse --> default_supplier_credentials
    attacker --> supplier_credential_abuse
    social_engineering_goal["[G10] Achieve Social Engineering-Based Disruption"]
    social_engineering_goal --> root
    operator_phishing["[A15] Operator Workstation (Email/HMI Access)"]
    operator_phishing --> social_engineering_goal
    phishing_vulnerability["[V15] Lack of Operator Security Awareness Training"]
    phishing_vulnerability --> operator_phishing
    hmi_credential_harvesting["[H15] Harvested HMI Credentials via Phishing Campaign"]
    hmi_credential_harvesting --> phishing_vulnerability
    attacker --> hmi_credential_harvesting
    fake_erp_messages["[A16] ERP-MES Communication Channel"]
    fake_erp_messages --> social_engineering_goal
    erp_message_spoofing["[V16] Lack of Message Authentication Between ERP and MES"]
    erp_message_spoofing --> fake_erp_messages
    unauthorized_production_changes["[H16] Spoofed ERP Messages Triggering Unauthorized Production Changes"]
    unauthorized_production_changes --> erp_message_spoofing
    attacker --> unauthorized_production_changes
    physical_goal["[G11] Achieve Physical Access-Based Disruption"]
    physical_goal --> root
    plc_programming_port["[A17] PLC Physical Programming Port (RS-232/USB)"]
    plc_programming_port --> physical_goal
    unsecured_plc_port["[V17] Unsecured Physical Access to PLC Programming Interface"]
    unsecured_plc_port --> plc_programming_port
    plc_logic_tampering["[H17] Direct Tampering with PLC Ladder Logic via Physical Access"]
    plc_logic_tampering --> unsecured_plc_port
    attacker --> plc_logic_tampering
    sensor_actuator_tampering["[A18] Field-Level Sensors/Actuators (4-20mA/I/O Links)"]
    sensor_actuator_tampering --> physical_goal
    unprotected_field_wiring["[V18] Unprotected Field Wiring Susceptible to Signal Injection"]
    unprotected_field_wiring --> sensor_actuator_tampering
    sensor_spoofing_physical["[H18] Physical Spoofing of Sensor Signals (e.g., Temperature/Pressure)"]
    sensor_spoofing_physical --> unprotected_field_wiring
    attacker --> sensor_spoofing_physical