graph BT
    root["[G01] CPS Disruption: Compromise Communications-Based Train Control (CBTC) System Operations"]
    spoof_train_wireless_comm["[H01] Spoof Train Identity via Wireless Communication Exploits"]
    spoof_train_wireless_comm --> root
    weak_auth_wireless_protocol["[V01] Weak Authentication in CBTC Radio Protocol (e.g., IEEE 802.11p)"]
    weak_auth_wireless_protocol --> spoof_train_wireless_comm
    false_position_reports["[H02] False Train Position Reports to Zone Controller"]
    false_position_reports --> weak_auth_wireless_protocol
    miscalculated_train_separation["[H03] Miscalculation of Train Separation Leading to Collisions"]
    miscalculated_train_separation --> false_position_reports
    attacker["[U01] Attacker"]
    attacker --> miscalculated_train_separation
    compromised_onboard_systems["[A01] Onboard Train Systems (ATP/ATO Units)"]
    compromised_onboard_systems --> spoof_train_wireless_comm
    spoof_vital_signs["[V02] Spoofing Vital Signs (Speed/Direction) via Compromised Onboard Software"]
    spoof_vital_signs --> compromised_onboard_systems
    incorrect_movement_authorities["[H04] Incorrect Movement Authorities Issued by Zone Controller"]
    incorrect_movement_authorities --> spoof_vital_signs
    derailments_collisions["[H05] Derailments or Collisions Due to False Authorities"]
    derailments_collisions --> incorrect_movement_authorities
    attacker --> derailments_collisions
    tamper_wayside_equipment["[H06] Tamper with Wayside Equipment (Track Circuits/Interlockings)"]
    tamper_wayside_equipment --> root
    unauthorized_physical_access["[V03] Unauthorized Physical Access to Wayside Controllers"]
    unauthorized_physical_access --> tamper_wayside_equipment
    alter_track_circuit_params["[H07] Alter Track Circuit Parameters to Generate False Occupancy Reports"]
    alter_track_circuit_params --> unauthorized_physical_access
    incorrect_train_routing["[H08] Incorrect Train Routing Leading to Collisions"]
    incorrect_train_routing --> alter_track_circuit_params
    attacker --> incorrect_train_routing
    exploit_onboard_software_vuln["[A02] Train Onboard Software (e.g., Communication Stack with CVE-2020-25163)"]
    exploit_onboard_software_vuln --> tamper_wayside_equipment
    buffer_overflow_braking_system["[V04] Buffer Overflow in Braking System Control Logic"]
    buffer_overflow_braking_system --> exploit_onboard_software_vuln
    alter_braking_params["[H09] Altered Braking Parameters Causing Speed Limit Violations"]
    alter_braking_params --> buffer_overflow_braking_system
    derailments_due_to_speed["[H10] Derailments Due to Excessive Speed"]
    derailments_due_to_speed --> alter_braking_params
    attacker --> derailments_due_to_speed
    repudiation_event_data["[H11] Repudiation of Train Event Data (Event Recorder Tampering)"]
    repudiation_event_data --> root
    compromised_event_recorder["[A03] Train Event Recorder System"]
    compromised_event_recorder --> repudiation_event_data
    unauthorized_data_modification["[V05] Unauthorized Modification of Recorded Event Data"]
    unauthorized_data_modification --> compromised_event_recorder
    hindered_incident_investigation["[H12] Hindered Incident Investigations Due to Tampered Logs"]
    hindered_incident_investigation --> unauthorized_data_modification
    attacker --> hindered_incident_investigation
    info_disclosure_wireless["[H13] Information Disclosure via Wireless Protocol Exploits"]
    info_disclosure_wireless --> root
    vulnerable_encryption_scheme["[V06] Vulnerable Encryption in CBTC Radio (e.g., CVE-2019-1010218)"]
    vulnerable_encryption_scheme --> info_disclosure_wireless
    intercept_train_positions["[H14] Interception of Train Positions and Movement Authorities"]
    intercept_train_positions --> vulnerable_encryption_scheme
    targeted_operational_attacks["[H15] Enabled Targeted Attacks Using Intercepted Operational Data"]
    targeted_operational_attacks --> intercept_train_positions
    attacker --> targeted_operational_attacks
    dos_wireless_network["[H16] Denial-of-Service (DoS) on CBTC Wireless Network"]
    dos_wireless_network --> root
    wireless_network_vulnerability["[V07] Lack of Anti-Jamming/DoS Protections in CBTC Radio"]
    wireless_network_vulnerability --> dos_wireless_network
    overwhelm_communication_links["[H17] Overwhelm Train-to-Wayside Communication Links"]
    overwhelm_communication_links --> wireless_network_vulnerability
    loss_situational_awareness["[H18] Loss of Situational Awareness Leading to Collisions"]
    loss_situational_awareness --> overwhelm_communication_links
    attacker --> loss_situational_awareness
    elevation_of_privilege["[H19] Elevation of Privilege in Train Onboard Systems"]
    elevation_of_privilege --> root
    onboard_os_vulnerability["[A04] Onboard Operating System (e.g., CVE-2021-31956)"]
    onboard_os_vulnerability --> elevation_of_privilege
    privilege_escalation_flaw["[V08] Privilege Escalation Vulnerability in Train Control Software"]
    privilege_escalation_flaw --> onboard_os_vulnerability
    unauthorized_control_commands["[H20] Issuance of Unauthorized Control Commands"]
    unauthorized_control_commands --> privilege_escalation_flaw
    safety_incidents_from_unauthorized_commands["[H21] Safety Incidents from Unauthorized Commands"]
    safety_incidents_from_unauthorized_commands --> unauthorized_control_commands
    attacker --> safety_incidents_from_unauthorized_commands
    lateral_movement_passenger_systems["[H22] Lateral Movement from Passenger Systems to Train Control"]
    lateral_movement_passenger_systems --> root
    weak_segmentation_passenger_network["[V09] Weak Network Segmentation Between Passenger and Control Systems"]
    weak_segmentation_passenger_network --> lateral_movement_passenger_systems
    compromised_passenger_info_system["[A05] Passenger Information System (Displays/Announcements)"]
    compromised_passenger_info_system --> weak_segmentation_passenger_network
    pivot_to_train_control["[H23] Pivot from Passenger System to Vital Train Control Networks"]
    pivot_to_train_control --> compromised_passenger_info_system
    safety_incidents_from_lateral_movement["[H24] Safety Incidents Due to Compromised Train Control"]
    safety_incidents_from_lateral_movement --> pivot_to_train_control
    attacker --> safety_incidents_from_lateral_movement
    time_synchronization_attack["[H25] Time Synchronization Attack (PTP Spoofing)"]
    time_synchronization_attack --> root
    compromised_ptp_grandmaster["[A06] PTP Grandmaster Clock"]
    compromised_ptp_grandmaster --> time_synchronization_attack
    ptp_spoofing_vulnerability["[V10] Lack of PTP Authentication Enabling Spoofing"]
    ptp_spoofing_vulnerability --> compromised_ptp_grandmaster
    desynchronized_train_localization["[H26] Desynchronized Train Localization Leading to Collisions"]
    desynchronized_train_localization --> ptp_spoofing_vulnerability
    attacker --> desynchronized_train_localization
    supply_chain_compromise["[H27] Supply Chain Compromise (Malicious Firmware/Updates)"]
    supply_chain_compromise --> root
    third_party_vendor_access["[A07] Third-Party Vendor Update Mechanisms (SFTP/Proprietary Protocols)"]
    third_party_vendor_access --> supply_chain_compromise
    trojaned_firmware_updates["[V11] Trojaned Firmware Updates for Wayside/Trainborne Controllers"]
    trojaned_firmware_updates --> third_party_vendor_access
    embedded_backdoors_in_critical_systems["[H28] Embedded Backdoors in Safety-Critical Systems"]
    embedded_backdoors_in_critical_systems --> trojaned_firmware_updates
    attacker --> embedded_backdoors_in_critical_systems
    counterfeit_wayside_components["[A08] Counterfeit Wayside Equipment (e.g., Switch Machines)"]
    counterfeit_wayside_components --> supply_chain_compromise
    hidden_backdoor_in_hardware["[V12] Hidden Backdoors in Counterfeit Hardware"]
    hidden_backdoor_in_hardware --> counterfeit_wayside_components
    unauthorized_control_via_backdoor["[H29] Unauthorized Control of Track Switches/Signals via Backdoor"]
    unauthorized_control_via_backdoor --> hidden_backdoor_in_hardware
    attacker --> unauthorized_control_via_backdoor
    social_engineering_operator["[H30] Social Engineering of Train Operators/Maintenance Personnel"]
    social_engineering_operator --> root
    human_factor_vulnerabilities["[V13] Lack of Multi-Factor Authentication (MFA) for Critical HMI Actions"]
    human_factor_vulnerabilities --> social_engineering_operator
    unauthorized_manual_overrides["[H31] Unauthorized Manual Overrides of Safety Systems"]
    unauthorized_manual_overrides --> human_factor_vulnerabilities
    collisions_due_to_human_error["[H32] Collisions or Derailments Due to Disabled Safeguards"]
    collisions_due_to_human_error --> unauthorized_manual_overrides
    attacker --> collisions_due_to_human_error
    phishing_maintenance_personnel["[V14] Phishing Attacks Targeting Maintenance Personnel Credentials"]
    phishing_maintenance_personnel --> social_engineering_operator
    compromised_engineering_workstations["[A09] Engineering Workstations with Configuration Access"]
    compromised_engineering_workstations --> phishing_maintenance_personnel
    malicious_configuration_changes["[H33] Malicious Changes to Signal Timing or Train Schedules"]
    malicious_configuration_changes --> compromised_engineering_workstations
    operational_disruptions_from_misconfiguration["[H34] Operational Disruptions or Safety Incidents from Misconfigurations"]
    operational_disruptions_from_misconfiguration --> malicious_configuration_changes
    attacker --> operational_disruptions_from_misconfiguration
    remote_access_exploits["[H35] Exploitation of Remote Access Gateways (VPN/Jump Servers)"]
    remote_access_exploits --> root
    vulnerable_vpn_implementations["[V15] Unpatched VPN Vulnerabilities (e.g., IPSec Flaws)"]
    vulnerable_vpn_implementations --> remote_access_exploits
    unauthorized_remote_command_execution["[H36] Unauthorized Remote Command Execution on Wayside Controllers"]
    unauthorized_remote_command_execution --> vulnerable_vpn_implementations
    disrupt_train_routing["[H37] Disruption of Train Routing or Signal Control"]
    disrupt_train_routing --> unauthorized_remote_command_execution
    attacker --> disrupt_train_routing
    credential_stuffing_jump_servers["[V16] Weak Credentials on Jump Servers Enabling Brute Force"]
    credential_stuffing_jump_servers --> remote_access_exploits
    compromised_engineering_vlans["[A10] Engineering VLANs with Access to Firmware Deployment Systems"]
    compromised_engineering_vlans --> credential_stuffing_jump_servers
    deploy_malicious_firmware["[H38] Deployment of Malicious Firmware to Trainborne Systems"]
    deploy_malicious_firmware --> compromised_engineering_vlans
    system-wide_compromise_via_remote_access["[H39] System-Wide Compromise via Remote Access Pathways"]
    system-wide_compromise_via_remote_access --> deploy_malicious_firmware
    attacker --> system-wide_compromise_via_remote_access
    physical_usb_attacks["[H40] Physical USB-Based Attacks on Wayside/Trainborne Systems"]
    physical_usb_attacks --> root
    unsecured_usb_ports["[V17] Unsecured USB Ports on Wayside Controllers or Onboard Units"]
    unsecured_usb_ports --> physical_usb_attacks
    malicious_firmware_via_usb["[H41] Injection of Malicious Firmware via USB (e.g., BadUSB)"]
    malicious_firmware_via_usb --> unsecured_usb_ports
    compromise_vital_control_systems["[H42] Compromise of Vital Control Systems (e.g., ATP/Interlockings)"]
    compromise_vital_control_systems --> malicious_firmware_via_usb
    attacker --> compromise_vital_control_systems
    outdated_av_maintenance_laptops["[A11] Maintenance Laptops with Outdated Antivirus"]
    outdated_av_maintenance_laptops --> physical_usb_attacks
    malware_spread_to_engineering_network["[V18] Malware Spread from Maintenance Laptops to Engineering Networks"]
    malware_spread_to_engineering_network --> outdated_av_maintenance_laptops
    lateral_movement_to_ccs["[H43] Lateral Movement to Central Control System (CCS)"]
    lateral_movement_to_ccs --> malware_spread_to_engineering_network
    system_wide_infection["[H44] System-Wide Infection Leading to Operational Halt"]
    system_wide_infection --> lateral_movement_to_ccs
    attacker --> system_wide_infection