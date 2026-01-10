graph BT
    root["[G01] Disruption or Stoppage of Cyber-Physical System Operations in Automotive Door Assembly Line"]
    spoofing_path["[G02] Spoof Legitimate Commands to Disrupt Operations"]
    spoofing_path --> root
    plc_asset["[A01] PLCs Controlling Robotic Arms and Conveyor Systems"]
    plc_asset --> spoofing_path
    plc_auth_vuln["[V01] Authentication Bypass Vulnerability (CVE-2021-3474) in PLC Firmware"]
    plc_auth_vuln --> plc_asset
    plc_unpatched["[A02] Unpatched PLCs with Default or Weak Credentials"]
    plc_unpatched --> plc_auth_vuln
    attacker["[U01] Attacker"]
    attacker --> plc_unpatched
    plc_spoof_hazard["[H01] Spoofed Commands Sent to Robotic Arms via Compromised Engineering Workstation"]
    plc_spoof_hazard --> plc_asset
    robotic_misalignment["[H02] Misalignment or Erratic Movement of Robotic Arms Due to Spoofed Calibration Commands"]
    robotic_misalignment --> plc_spoof_hazard
    attacker["[U01] Attacker"]
    attacker --> robotic_misalignment
    production_defects["[H03] Production of Defective Car Doors Due to Incorrect Assembly Parameters"]
    production_defects --> plc_spoof_hazard
    attacker["[U01] Attacker"]
    attacker --> production_defects
    tampering_path["[G03] Tamper with HMI or PLC Parameters to Cause Physical Damage"]
    tampering_path --> root
    hmi_asset["[A03] HMI Touchscreens for Conveyor Belt and Robotic Arm Control"]
    hmi_asset --> tampering_path
    hmi_software_vuln["[V02] Parameter Tampering Vulnerability in HMI Software (CVE-2020-14497)"]
    hmi_software_vuln --> hmi_asset
    hmi_unsecured_access["[A04] Unsecured Physical or Remote Access to HMI Terminals"]
    hmi_unsecured_access --> hmi_software_vuln
    attacker["[U01] Attacker"]
    attacker --> hmi_unsecured_access
    conveyor_tamper_hazard["[H04] Unsafe Conveyor Belt Speed Settings Due to Tampered HMI Parameters"]
    conveyor_tamper_hazard --> hmi_asset
    mechanical_failure["[H05] Mechanical Failure or Overheating of Conveyor Motors"]
    mechanical_failure --> conveyor_tamper_hazard
    attacker["[U01] Attacker"]
    attacker --> mechanical_failure
    worker_injury["[H06] Worker Injury Due to Uncontrolled Conveyor Movement"]
    worker_injury --> conveyor_tamper_hazard
    attacker["[U01] Attacker"]
    attacker --> worker_injury
    repudiation_path["[G04] Delete or Alter Logs to Conceal Malicious Activity"]
    repudiation_path --> root
    scada_logging["[A05] SCADA System Logging and Historian Database"]
    scada_logging --> repudiation_path
    log_deletion_vuln["[V03] Log Deletion/Manipulation Vulnerability (CVE-2019-10994) in SCADA Software"]
    log_deletion_vuln --> scada_logging
    scada_admin_access["[A06] Compromised SCADA Admin Credentials via Phishing or Brute Force"]
    scada_admin_access --> log_deletion_vuln
    attacker["[U01] Attacker"]
    attacker --> scada_admin_access
    log_tamper_hazard["[H07] Deletion of Critical Logs Recording Robotic Arm Actions"]
    log_tamper_hazard --> scada_logging
    undetected_attacks["[H08] Prolonged Undetected Attacks Due to Lack of Audit Trails"]
    undetected_attacks --> log_tamper_hazard
    attacker["[U01] Attacker"]
    attacker --> undetected_attacks
    compliance_violation["[H09] Regulatory Compliance Violations Due to Missing Logs"]
    compliance_violation --> log_tamper_hazard
    attacker["[U01] Attacker"]
    attacker --> compliance_violation
    info_disclosure_path["[G05] Exfiltrate Sensitive Production Data for Industrial Espionage"]
    info_disclosure_path --> root
    industrial_router["[A07] Industrial Routers and Cloud Gateway Interfaces"]
    industrial_router --> info_disclosure_path
    router_exfil_vuln["[V04] Data Exfiltration Vulnerability in Industrial Routers (CVE-2021-22893)"]
    router_exfil_vuln --> industrial_router
    unencrypted_comms["[A08] Unencrypted Communication Between Routers and Cloud Services"]
    unencrypted_comms --> router_exfil_vuln
    attacker["[U01] Attacker"]
    attacker --> unencrypted_comms
    data_leak_hazard["[H10] Interception of Proprietary Door Designs and Production Schedules"]
    data_leak_hazard --> industrial_router
    ip_theft["[H11] Theft of Intellectual Property Leading to Competitive Disadvantage"]
    ip_theft --> data_leak_hazard
    attacker["[U01] Attacker"]
    attacker --> ip_theft
    financial_loss["[H12] Financial Losses Due to Espionage or Blackmail"]
    financial_loss --> data_leak_hazard
    attacker["[U01] Attacker"]
    attacker --> financial_loss
    dos_path["[G06] Disrupt SCADA Network Availability via Denial-of-Service"]
    dos_path --> root
    scada_network["[A09] SCADA Network Communication Protocols (OPC UA, Modbus TCP)"]
    scada_network --> dos_path
    dos_vuln["[V05] Network Flooding Vulnerability in SCADA Protocols (CVE-2020-13576)"]
    dos_vuln --> scada_network
    unsegmented_network["[A10] Poorly Segmented IT/OT Network Allowing DoS Propagation"]
    unsegmented_network --> dos_vuln
    attacker["[U01] Attacker"]
    attacker --> unsegmented_network
    scada_outage_hazard["[H13] SCADA System Unresponsiveness Due to Malicious Packet Flooding"]
    scada_outage_hazard --> scada_network
    production_halt["[H14] Complete Halt of Production Line Due to SCADA Outage"]
    production_halt --> scada_outage_hazard
    attacker["[U01] Attacker"]
    attacker --> production_halt
    manual_override_risk["[H15] Risk of Manual Override Errors During Downtime"]
    manual_override_risk --> scada_outage_hazard
    attacker["[U01] Attacker"]
    attacker --> manual_override_risk
    priv_escalation_path["[G07] Elevate Privileges to Gain Control Over Critical PLCs"]
    priv_escalation_path --> root
    access_control_system["[A11] OT Access Control System for PLC Programming"]
    access_control_system --> priv_escalation_path
    priv_esc_vuln["[V06] Privilege Escalation Vulnerability (CVE-2021-27108) in Access Control Software"]
    priv_esc_vuln --> access_control_system
    default_service_accounts["[A12] Default or Shared Service Accounts with Elevated Privileges"]
    default_service_accounts --> priv_esc_vuln
    attacker["[U01] Attacker"]
    attacker --> default_service_accounts
    plc_takeover_hazard["[H16] Unauthorized Administrative Access to Robotic Arm PLCs"]
    plc_takeover_hazard --> access_control_system
    unsafe_operations["[H17] Unsafe or Unintended Operations of Robotic Arms"]
    unsafe_operations --> plc_takeover_hazard
    attacker["[U01] Attacker"]
    attacker --> unsafe_operations
    equipment_damage["[H18] Physical Damage to Robotic Arms or Conveyor Systems"]
    equipment_damage --> plc_takeover_hazard
    attacker["[U01] Attacker"]
    attacker --> equipment_damage
    lateral_movement_path["[G08] Move Laterally from IT to OT to Compromise Field Devices"]
    lateral_movement_path --> root
    it_ot_gateway["[A13] IT/OT Gateway (Firewalls, DMZ, Engineering Workstations)"]
    it_ot_gateway --> lateral_movement_path
    lateral_movement_vuln["[V07] Network Segmentation Bypass Vulnerability (CVE-2020-1472)"]
    lateral_movement_vuln --> it_ot_gateway
    compromised_it_host["[A14] Compromised IT Host (e.g., Engineer’s Laptop) with OT Network Access"]
    compromised_it_host --> lateral_movement_vuln
    attacker["[U01] Attacker"]
    attacker --> compromised_it_host
    field_device_compromise["[H19] Compromise of PLCs or Fieldbus Devices via Lateral Movement"]
    field_device_compromise --> it_ot_gateway
    conveyor_disruption["[H20] Disruption of Conveyor Belt Synchronization Leading to Production Delays"]
    conveyor_disruption --> field_device_compromise
    attacker["[U01] Attacker"]
    attacker --> conveyor_disruption
    safety_system_bypass["[H21] Bypass of Safety Instrumented Systems (SIS) via PLC Tampering"]
    safety_system_bypass --> field_device_compromise
    attacker["[U01] Attacker"]
    attacker --> safety_system_bypass
    supply_chain_path["[G09] Compromise Supply Chain to Introduce Malicious Firmware or Components"]
    supply_chain_path --> root
    vendor_update_mechanism["[A15] Vendor Firmware Update Mechanism for PLCs/HMIs"]
    vendor_update_mechanism --> supply_chain_path
    firmware_tamper_vuln["[V08] Lack of Firmware Integrity Checks in Update Process"]
    firmware_tamper_vuln --> vendor_update_mechanism
    untrusted_update_source["[A16] Untrusted or Compromised Vendor Update Servers"]
    untrusted_update_source --> firmware_tamper_vuln
    attacker["[U01] Attacker"]
    attacker --> untrusted_update_source
    malicious_firmware_hazard["[H22] Deployment of Malicious Firmware to PLCs via Legitimate Update Channel"]
    malicious_firmware_hazard --> vendor_update_mechanism
    backdoor_installation["[H23] Installation of Persistent Backdoors in PLC Firmware"]
    backdoor_installation --> malicious_firmware_hazard
    attacker["[U01] Attacker"]
    attacker --> backdoor_installation
    sabotage_triggers["[H24] Sabotage Triggers Embedded in Firmware (e.g., Time-Based or Event-Based)"]
    sabotage_triggers --> malicious_firmware_hazard
    attacker["[U01] Attacker"]
    attacker --> sabotage_triggers
    physical_tampering_path["[G10] Physically Tamper with Field Devices or Safety Systems"]
    physical_tampering_path --> root
    field_devices["[A17] Field Devices (Sensors, Actuators, Safety Relays)"]
    field_devices --> physical_tampering_path
    physical_access_vuln["[V09] Unsecured Physical Access to PLC Cabinets or Fieldbus Junctions"]
    physical_access_vuln --> field_devices
    unlocked_cabinets["[A18] Unlocked or Poorly Secured PLC Cabinets in Production Floor"]
    unlocked_cabinets --> physical_access_vuln
    attacker["[U01] Attacker"]
    attacker --> unlocked_cabinets
    safety_bypass_hazard["[H25] Physical Tampering with Safety Instrumented Systems (SIS) Wiring"]
    safety_bypass_hazard --> field_devices
    emergency_stop_failure["[H26] Failure of Emergency Stop Functions Due to Tampered Wiring"]
    emergency_stop_failure --> safety_bypass_hazard
    attacker["[U01] Attacker"]
    attacker --> emergency_stop_failure
    false_safety_signals["[H27] Injection of False Safety Signals to Bypass Interlocks"]
    false_safety_signals --> safety_bypass_hazard
    attacker["[U01] Attacker"]
    attacker --> false_safety_signals