graph BT
    root["[G00] Disrupt or Stop Cyber-Physical System Operations in a Nuclear Power Plant"]
    spoofing["[H01] Spoofing of Legitimate Commands or Data"]
    spoofing --> root
    hmi_spoof["[H02] Spoof HMI Commands to PLCs"]
    hmi_spoof --> spoofing
    weak_auth_hmi["[V01] Weak or Default HMI Authentication (e.g., CVE-2017-9627)"]
    weak_auth_hmi --> hmi_spoof
    hmi_software["[A01] HMI Software (e.g., Siemens WinCC, Rockwell FactoryTalk)"]
    hmi_software --> weak_auth_hmi
    attacker["[U01] Attacker"]
    attacker --> hmi_software
    unencrypted_comms["[V02] Unencrypted HMI-PLC Communication (e.g., Modbus TCP, DNP3)"]
    unencrypted_comms --> hmi_spoof
    network_sniffing_tools["[A02] Network Sniffing Tools (e.g., Wireshark, tcpdump)"]
    network_sniffing_tools --> unencrypted_comms
    attacker["[U01] Attacker"]
    attacker --> network_sniffing_tools
    sensor_spoof["[H03] Spoof Sensor Data to Mislead Control Logic"]
    sensor_spoof --> spoofing
    unauthenticated_fieldbus["[V03] Unauthenticated Fieldbus Protocols (e.g., HART, Profibus)"]
    unauthenticated_fieldbus --> sensor_spoof
    field_devices["[A03] Field Devices (Sensors/Actuators)"]
    field_devices --> unauthenticated_fieldbus
    attacker["[U01] Attacker"]
    attacker --> field_devices
    default_credentials["[V04] Default Credentials on Intelligent Electronic Devices (IEDs)"]
    default_credentials --> sensor_spoof
    ieds["[A04] Intelligent Electronic Devices (IEDs)"]
    ieds --> default_credentials
    attacker["[U01] Attacker"]
    attacker --> ieds
    tampering["[H04] Tampering with Safety or Control Logic"]
    tampering --> root
    sis_tamper["[H05] Tamper with Safety Instrumented Systems (SIS)"]
    sis_tamper --> tampering
    engineering_workstation_access["[V05] Unauthorized Access to Engineering Workstations (e.g., CVE-2018-4837)"]
    engineering_workstation_access --> sis_tamper
    engineering_workstations["[A05] Engineering Workstations (e.g., Siemens TIA Portal, Schneider Unity Pro)"]
    engineering_workstations --> engineering_workstation_access
    attacker["[U01] Attacker"]
    attacker --> engineering_workstations
    firmware_backdoor["[V06] Backdoored Firmware in SIS Controllers"]
    firmware_backdoor --> sis_tamper
    sis_controllers["[A06] SIS Controllers (e.g., Honeywell Safety Manager, Siemens S7-400F)"]
    sis_controllers --> firmware_backdoor
    attacker["[U01] Attacker"]
    attacker --> sis_controllers
    plc_tamper["[H06] Tamper with PLC Control Logic"]
    plc_tamper --> tampering
    unauthorized_logic_upload["[V07] Unauthorized PLC Logic Upload (e.g., via compromised engineering software)"]
    unauthorized_logic_upload --> plc_tamper
    plc_programming_software["[A07] PLC Programming Software (e.g., Rockwell Studio 5000, Siemens Step 7)"]
    plc_programming_software --> unauthorized_logic_upload
    attacker["[U01] Attacker"]
    attacker --> plc_programming_software
    plc_memory_corruption["[V08] PLC Memory Corruption via Buffer Overflow (e.g., CVE-2020-25159)"]
    plc_memory_corruption --> plc_tamper
    plcs["[A08] Programmable Logic Controllers (PLCs)"]
    plcs --> plc_memory_corruption
    attacker["[U01] Attacker"]
    attacker --> plcs
    repudiation["[H07] Repudiation via Log or Audit Trail Manipulation"]
    repudiation --> root
    historian_tamper["[H08] Tamper with Historian Server Logs"]
    historian_tamper --> repudiation
    weak_integrity_checks["[V09] Weak Integrity Checks on Historian Data (e.g., no digital signatures)"]
    weak_integrity_checks --> historian_tamper
    historian_servers["[A09] Historian Servers (e.g., OSIsoft PI, Honeywell PHD)"]
    historian_servers --> weak_integrity_checks
    attacker["[U01] Attacker"]
    attacker --> historian_servers
    unauthorized_historian_access["[V10] Unauthorized Access to Historian (e.g., via exploited credentials)"]
    unauthorized_historian_access --> historian_tamper
    historian_access_credentials["[A10] Historian Access Credentials (e.g., stored in cleartext)"]
    historian_access_credentials --> unauthorized_historian_access
    attacker["[U01] Attacker"]
    attacker --> historian_access_credentials
    syslog_tamper["[H09] Tamper with Network Device Logs (e.g., Firewalls, Switches)"]
    syslog_tamper --> repudiation
    default_syslog_credentials["[V11] Default Credentials on Network Devices (e.g., Cisco, Hirschmann)"]
    default_syslog_credentials --> syslog_tamper
    network_devices["[A11] Network Devices (Switches, Routers, Firewalls)"]
    network_devices --> default_syslog_credentials
    attacker["[U01] Attacker"]
    attacker --> network_devices
    unencrypted_syslog["[V12] Unencrypted Syslog Transmission"]
    unencrypted_syslog --> syslog_tamper
    syslog_servers["[A12] Syslog Servers"]
    syslog_servers --> unencrypted_syslog
    attacker["[U01] Attacker"]
    attacker --> syslog_servers
    info_disclosure["[H10] Information Disclosure via Unauthorized Access"]
    info_disclosure --> root
    network_traffic_intercept["[H11] Intercept Unencrypted Network Traffic"]
    network_traffic_intercept --> info_disclosure
    unencrypted_ics_protocols["[V13] Use of Unencrypted ICS Protocols (e.g., Modbus, DNP3)"]
    unencrypted_ics_protocols --> network_traffic_intercept
    industrial_switches["[A13] Industrial Switches/Routers (e.g., Cisco IE, Moxa)"]
    industrial_switches --> unencrypted_ics_protocols
    attacker["[U01] Attacker"]
    attacker --> industrial_switches
    mitm_attack["[V14] Man-in-the-Middle (MITM) via ARP Spoofing or DNS Poisoning"]
    mitm_attack --> network_traffic_intercept
    network_infrastructure["[A14] Network Infrastructure (e.g., VLANs, Subnets)"]
    network_infrastructure --> mitm_attack
    attacker["[U01] Attacker"]
    attacker --> network_infrastructure
    data_exfiltration["[H12] Exfiltrate Sensitive Operational Data"]
    data_exfiltration --> info_disclosure
    unsecured_remote_access["[V15] Unsecured Remote Access Gateways (e.g., VPN, RDP)"]
    unsecured_remote_access --> data_exfiltration
    remote_access_gateways["[A15] Remote Access Gateways (e.g., OpenVPN, Microsoft RDP)"]
    remote_access_gateways --> unsecured_remote_access
    attacker["[U01] Attacker"]
    attacker --> remote_access_gateways
    unmonitored_data_transfers["[V16] Unmonitored Data Transfers via USB or Removable Media"]
    unmonitored_data_transfers --> data_exfiltration
    removable_media["[A16] Removable Media (USB Drives, External HDDs)"]
    removable_media --> unmonitored_data_transfers
    attacker["[U01] Attacker"]
    attacker --> removable_media
    dos["[H13] Denial of Service (DoS) on Critical Systems"]
    dos --> root
    network_dos["[H14] Network Flooding or Protocol-Specific DoS"]
    network_dos --> dos
    unpatched_network_devices["[V17] Unpatched Network Devices (e.g., CVE-2016-1404)"]
    unpatched_network_devices --> network_dos
    industrial_firewalls["[A17] Industrial Firewalls (e.g., Palo Alto, Fortinet)"]
    industrial_firewalls --> unpatched_network_devices
    attacker["[U01] Attacker"]
    attacker --> industrial_firewalls
    protocol_fuzzing["[V18] Protocol Fuzzing (e.g., Modbus, DNP3)"]
    protocol_fuzzing --> network_dos
    protocol_fuzzing_tools["[A18] Protocol Fuzzing Tools (e.g., Sulley, Boofuzz)"]
    protocol_fuzzing_tools --> protocol_fuzzing
    attacker["[U01] Attacker"]
    attacker --> protocol_fuzzing_tools
    plc_dos["[H15] PLC or RTU Overload via Malicious Commands"]
    plc_dos --> dos
    plc_resource_exhaustion["[V19] PLC Resource Exhaustion (e.g., excessive I/O scans)"]
    plc_resource_exhaustion --> plc_dos
    plcs_rtus["[A19] PLCs/RTUs (e.g., Siemens S7, Schneider Quantum)"]
    plcs_rtus --> plc_resource_exhaustion
    attacker["[U01] Attacker"]
    attacker --> plcs_rtus
    firmware_corruption["[V20] PLC Firmware Corruption via Malformed Packets"]
    firmware_corruption --> plc_dos
    plc_firmware["[A20] PLC Firmware (e.g., outdated or vulnerable versions)"]
    plc_firmware --> firmware_corruption
    attacker["[U01] Attacker"]
    attacker --> plc_firmware
    privilege_escalation["[H16] Elevation of Privilege in ICS Systems"]
    privilege_escalation --> root
    exploit_software_vulnerabilities["[H17] Exploit Software Vulnerabilities for Privilege Escalation"]
    exploit_software_vulnerabilities --> privilege_escalation
    unpatched_ics_software["[V21] Unpatched ICS Software (e.g., CVE-2020-6973)"]
    unpatched_ics_software --> exploit_software_vulnerabilities
    ics_software["[A21] ICS Software (e.g., SCADA, DCS, HMI)"]
    ics_software --> unpatched_ics_software
    attacker["[U01] Attacker"]
    attacker --> ics_software
    privilege_escalation_exploits["[V22] Known Privilege Escalation Exploits (e.g., DirtyCow, EternalBlue)"]
    privilege_escalation_exploits --> exploit_software_vulnerabilities
    exploit_databases["[A22] Exploit Databases (e.g., Metasploit, Exploit-DB)"]
    exploit_databases --> privilege_escalation_exploits
    attacker["[U01] Attacker"]
    attacker --> exploit_databases
    credential_theft["[H18] Steal or Forge Credentials for Higher Privileges"]
    credential_theft --> privilege_escalation
    weak_password_storage["[V23] Weak Password Storage (e.g., plaintext, reversible encryption)"]
    weak_password_storage --> credential_theft
    credential_stores["[A23] Credential Stores (e.g., Windows SAM, Linux /etc/shadow)"]
    credential_stores --> weak_password_storage
    attacker["[U01] Attacker"]
    attacker --> credential_stores
    pass_the_hash["[V24] Pass-the-Hash or Kerberoasting Attacks"]
    pass_the_hash --> credential_theft
    authentication_protocols["[A24] Authentication Protocols (e.g., NTLM, Kerberos)"]
    authentication_protocols --> pass_the_hash
    attacker["[U01] Attacker"]
    attacker --> authentication_protocols
    lateral_movement["[H19] Lateral Movement from IT to OT Networks"]
    lateral_movement --> root
    exploit_weak_segmentation["[H20] Exploit Weak Network Segmentation"]
    exploit_weak_segmentation --> lateral_movement
    misconfigured_firewalls["[V25] Misconfigured Firewalls or ACLs"]
    misconfigured_firewalls --> exploit_weak_segmentation
    firewall_rules["[A25] Firewall Rules and Access Control Lists (ACLs)"]
    firewall_rules --> misconfigured_firewalls
    attacker["[U01] Attacker"]
    attacker --> firewall_rules
    default_vlan_configurations["[V26] Default VLAN Configurations Allowing Inter-VLAN Routing"]
    default_vlan_configurations --> exploit_weak_segmentation
    vlan_configurations["[A26] VLAN Configurations (e.g., Cisco VLANs, Moxa Turbo Ring)"]
    vlan_configurations --> default_vlan_configurations
    attacker["[U01] Attacker"]
    attacker --> vlan_configurations
    abuse_trusted_relationships["[H21] Abuse Trusted Relationships Between Systems"]
    abuse_trusted_relationships --> lateral_movement
    trusted_automatic_logins["[V27] Trusted Automatic Logins (e.g., Windows Domain Trusts, SSH Keys)"]
    trusted_automatic_logins --> abuse_trusted_relationships
    trust_relationships["[A27] Trust Relationships (e.g., Active Directory Trusts, SSH Authorized Keys)"]
    trust_relationships --> trusted_automatic_logins
    attacker["[U01] Attacker"]
    attacker --> trust_relationships
    shared_service_accounts["[V28] Shared Service Accounts with Excessive Privileges"]
    shared_service_accounts --> abuse_trusted_relationships
    service_accounts["[A28] Service Accounts (e.g., SQL Server Accounts, ICS Service Users)"]
    service_accounts --> shared_service_accounts
    attacker["[U01] Attacker"]
    attacker --> service_accounts
    supply_chain["[H22] Supply Chain Compromise"]
    supply_chain --> root
    compromised_vendor_updates["[H23] Compromised Vendor Software or Firmware Updates"]
    compromised_vendor_updates --> supply_chain
    unverified_update_sources["[V29] Unverified Update Sources (e.g., no cryptographic signing)"]
    unverified_update_sources --> compromised_vendor_updates
    vendor_update_portals["[A29] Vendor Update Portals (e.g., Siemens TIA Portal Updates, Rockwell Patch Manager)"]
    vendor_update_portals --> unverified_update_sources
    attacker["[U01] Attacker"]
    attacker --> vendor_update_portals
    backdoored_firmware["[V30] Backdoored Firmware in PLCs or IEDs"]
    backdoored_firmware --> compromised_vendor_updates
    firmware_images["[A30] Firmware Images (e.g., PLC, RTU, IED Firmware)"]
    firmware_images --> backdoored_firmware
    attacker["[U01] Attacker"]
    attacker --> firmware_images
    counterfeit_components["[H24] Counterfeit or Tampered Hardware Components"]
    counterfeit_components --> supply_chain
    unverified_hardware_sources["[V31] Unverified Hardware Sources (e.g., gray market suppliers)"]
    unverified_hardware_sources --> counterfeit_components
    hardware_procurement["[A31] Hardware Procurement Channels (e.g., Distributors, Resellers)"]
    hardware_procurement --> unverified_hardware_sources
    attacker["[U01] Attacker"]
    attacker --> hardware_procurement
    hardware_trojan_horses["[V32] Hardware Trojan Horses in Field Devices"]
    hardware_trojan_horses --> counterfeit_components
    field_device_hardware["[A32] Field Device Hardware (e.g., Sensors, Actuators, IEDs)"]
    field_device_hardware --> hardware_trojan_horses
    attacker["[U01] Attacker"]
    attacker --> field_device_hardware
    physical_intrusion["[H25] Physical Intrusion and Local Access Exploits"]
    physical_intrusion --> root
    unauthorized_physical_access["[H26] Unauthorized Physical Access to Control Rooms or Field Devices"]
    unauthorized_physical_access --> physical_intrusion
    weak_physical_security["[V33] Weak Physical Security (e.g., unsecured doors, lack of mantraps)"]
    weak_physical_security --> unauthorized_physical_access
    physical_access_points["[A33] Physical Access Points (e.g., Control Room Doors, Field Device Enclosures)"]
    physical_access_points --> weak_physical_security
    attacker["[U01] Attacker"]
    attacker --> physical_access_points
    social_engineering["[V34] Social Engineering (e.g., tailgating, impersonation)"]
    social_engineering --> unauthorized_physical_access
    plant_personnel["[A34] Plant Personnel (e.g., Operators, Engineers, Security Guards)"]
    plant_personnel --> social_engineering
    attacker["[U01] Attacker"]
    attacker --> plant_personnel
    local_device_exploitation["[H27] Exploit Local Device Interfaces (e.g., USB, Serial, Local HMI)"]
    local_device_exploitation --> physical_intrusion
    unsecured_local_interfaces["[V35] Unsecured Local Interfaces (e.g., USB ports, serial consoles)"]
    unsecured_local_interfaces --> local_device_exploitation
    local_interfaces["[A35] Local Interfaces (e.g., PLC USB Ports, HMI Consoles)"]
    local_interfaces --> unsecured_local_interfaces
    attacker["[U01] Attacker"]
    attacker --> local_interfaces
    default_local_credentials["[V36] Default Local Credentials on Field Devices"]
    default_local_credentials --> local_device_exploitation
    local_credentials["[A36] Local Credentials (e.g., Default PLC Passwords, HMI Local Accounts)"]
    local_credentials --> default_local_credentials
    attacker["[U01] Attacker"]
    attacker --> local_credentials
    time_synchronization_attack["[H28] Time Synchronization Attacks"]
    time_synchronization_attack --> root
    ntp_amplification["[H29] NTP Amplification or Spoofing"]
    ntp_amplification --> time_synchronization_attack
    unsecured_ntp_servers["[V37] Unsecured NTP Servers (e.g., no authentication, open to internet)"]
    unsecured_ntp_servers --> ntp_amplification
    ntp_servers["[A37] NTP Servers (e.g., Local NTP, GPS-Clock References)"]
    ntp_servers --> unsecured_ntp_servers
    attacker["[U01] Attacker"]
    attacker --> ntp_servers
    ntp_protocol_vulnerabilities["[V38] NTP Protocol Vulnerabilities (e.g., CVE-2013-5211)"]
    ntp_protocol_vulnerabilities --> ntp_amplification
    ntp_protocol["[A38] NTP Protocol Implementation"]
    ntp_protocol --> ntp_protocol_vulnerabilities
    attacker["[U01] Attacker"]
    attacker --> ntp_protocol
    ptp_delay_attack["[H30] PTP Delay Attack on Industrial Clocks"]
    ptp_delay_attack --> time_synchronization_attack
    unsecured_ptp_networks["[V39] Unsecured PTP Networks (e.g., no encryption, no authentication)"]
    unsecured_ptp_networks --> ptp_delay_attack
    ptp_networks["[A39] PTP Networks (e.g., IEEE 1588, Industrial Ethernet)"]
    ptp_networks --> unsecured_ptp_networks
    attacker["[U01] Attacker"]
    attacker --> ptp_networks
    ptp_injection["[V40] PTP Packet Injection or Replay"]
    ptp_injection --> ptp_delay_attack
    ptp_packets["[A40] PTP Packets (e.g., Sync, Follow_Up, Delay_Req)"]
    ptp_packets --> ptp_injection
    attacker["[U01] Attacker"]
    attacker --> ptp_packets