graph BT
    root["[G00] Disrupt or Stop Cyber-Physical System Operations (Railway CBTC)"]
    compromise_communication["[G01] Compromise Train-to-Wayside Communication"]
    compromise_communication --> root
    wireless_protocols["[A01] Wireless Communication Protocols (IEEE 802.11p, GSM-R, LTE-R)"]
    wireless_protocols --> compromise_communication
    protocol_vuln["[V01] Exploit Protocol Vulnerabilities (e.g., CVE-2021-3176, Log4Shell)"]
    protocol_vuln --> wireless_protocols
    spoof_train_id["[H01] Spoof Train Identity or Position Data"]
    spoof_train_id --> protocol_vuln
    false_signaling["[H02] Cause Incorrect Signaling Leading to Collisions/Derailements"]
    false_signaling --> spoof_train_id
    attacker["[U01] Attacker"]
    attacker --> false_signaling
    dos_wireless["[H03] Launch DoS on Wireless Channels (Jamming, Flooding)"]
    dos_wireless --> protocol_vuln
    comm_loss["[H04] Induce Loss of Train-Ground Communication"]
    comm_loss --> dos_wireless
    attacker["[U01] Attacker"]
    attacker --> comm_loss
    rogue_base_station["[A02] Deploy Rogue Base Station (Fake GSM-R Tower)"]
    rogue_base_station --> wireless_protocols
    mitm_attack["[V02] Perform Man-in-the-Middle (MITM) Attack on Train Comms"]
    mitm_attack --> rogue_base_station
    tamper_commands["[H05] Tamper with Movement Authorities or Braking Commands"]
    tamper_commands --> mitm_attack
    attacker["[U01] Attacker"]
    attacker --> tamper_commands
    compromise_wayside["[G02] Compromise Wayside Infrastructure"]
    compromise_wayside --> root
    trackside_assets["[A03] Trackside Assets (Zone Controllers, Signals, Points Machines)"]
    trackside_assets --> compromise_wayside
    physical_access["[V03] Gain Unauthorized Physical Access to Trackside Cabinets"]
    physical_access --> trackside_assets
    tamper_sensors["[H06] Tamper with Axle Counters/Balises to Spoof Occupancy"]
    tamper_sensors --> physical_access
    false_occupancy["[H07] Trigger False Track Occupancy or Clear Signals"]
    false_occupancy --> tamper_sensors
    attacker["[U01] Attacker"]
    attacker --> false_occupancy
    sabotage_power["[H08] Sabotage Power Supply to Wayside Controllers"]
    sabotage_power --> physical_access
    system_failure["[H09] Cause Fail-Safe Mode or System Shutdown"]
    system_failure --> sabotage_power
    attacker["[U01] Attacker"]
    attacker --> system_failure
    default_creds["[V04] Exploit Default/Hardcoded Credentials in PLCs/Radio Units"]
    default_creds --> trackside_assets
    unauth_access["[H10] Gain Unauthorized Remote Access to Wayside Systems"]
    unauth_access --> default_creds
    modify_logic["[H11] Modify Interlocking Logic or Signal Timing"]
    modify_logic --> unauth_access
    attacker["[U01] Attacker"]
    attacker --> modify_logic
    backbone_network["[A04] Backbone Network (Fiber Rings, Switches, Gateways)"]
    backbone_network --> compromise_wayside
    network_vuln["[V05] Exploit Network Vulnerabilities (e.g., CVE-2020-25705, RSTP Misconfig)"]
    network_vuln --> backbone_network
    dos_network["[H12] Launch DoS on Backbone (MPLS-TE Flooding, ARP Spoofing)"]
    dos_network --> network_vuln
    loss_supervision["[H13] Disrupt Central Supervision or Redundancy"]
    loss_supervision --> dos_network
    attacker["[U01] Attacker"]
    attacker --> loss_supervision
    lateral_movement["[H14] Move Laterally from IT to OT (e.g., via Misconfigured Firewall)"]
    lateral_movement --> network_vuln
    compromise_occ["[H15] Compromise Operations Control Center (OCC) Systems"]
    compromise_occ --> lateral_movement
    attacker["[U01] Attacker"]
    attacker --> compromise_occ
    compromise_trainborne["[G03] Compromise Trainborne Systems"]
    compromise_trainborne --> root
    onboard_assets["[A05] Onboard Assets (ATP/ATO Units, Vital Computers, TIU)"]
    onboard_assets --> compromise_trainborne
    firmware_vuln["[V06] Exploit Firmware Vulnerabilities (e.g., CVE-2021-34527)"]
    firmware_vuln --> onboard_assets
    tamper_atp["[H16] Tamper with ATP Braking Curves or Speed Limits"]
    tamper_atp --> firmware_vuln
    unsafe_operation["[H17] Force Unsafe Train Operation (Overspeed, Missed Stops)"]
    unsafe_operation --> tamper_atp
    attacker["[U01] Attacker"]
    attacker --> unsafe_operation
    maintenance_port["[A06] Onboard Maintenance Ports (USB, Ethernet, Diagnostic Connectors)"]
    maintenance_port --> onboard_assets
    unauth_fw_update["[V07] Perform Unauthorized Firmware Update via Port"]
    unauth_fw_update --> maintenance_port
    malicious_logic["[H18] Inject Malicious Logic into Vital Computer"]
    malicious_logic --> unauth_fw_update
    attacker["[U01] Attacker"]
    attacker --> malicious_logic
    gps_spoofing["[A07] GPS Receiver (for Positioning)"]
    gps_spoofing --> compromise_trainborne
    spoof_gps["[V08] Spoof GPS Signals to Falsify Train Position"]
    spoof_gps --> gps_spoofing
    incorrect_localization["[H19] Cause Incorrect Train Localization (Balise Mismatch)"]
    incorrect_localization --> spoof_gps
    signal_violation["[H20] Trigger Signal Violation or Wrong-Route Incursion"]
    signal_violation --> incorrect_localization
    attacker["[U01] Attacker"]
    attacker --> signal_violation
    compromise_supporting_it["[G04] Compromise Supporting IT Systems"]
    compromise_supporting_it --> root
    it_assets["[A08] IT Assets (Maintenance Workstations, Historian Servers, Remote Portals)"]
    it_assets --> compromise_supporting_it
    credential_theft["[V09] Steal Credentials via Phishing (e.g., CVE-2019-19781)"]
    credential_theft --> it_assets
    unauth_remote_access["[H21] Gain Unauthorized Remote Access via VPN/Jump Host"]
    unauth_remote_access --> credential_theft
    modify_schedules["[H22] Modify Train Schedules or Timetables (Non-Vital)"]
    modify_schedules --> unauth_remote_access
    attacker["[U01] Attacker"]
    attacker --> modify_schedules
    tamper_logs["[H23] Tamper with Historian Logs to Hide Attacks"]
    tamper_logs --> unauth_remote_access
    attacker["[U01] Attacker"]
    attacker --> tamper_logs
    supply_chain["[A09] Supply Chain (Third-Party Vendors, Firmware Updates)"]
    supply_chain --> it_assets
    malicious_update["[V10] Inject Malicious Code in Firmware Update (e.g., via CVE-2021-3806)"]
    malicious_update --> supply_chain
    persistent_compromise["[H24] Achieve Persistent Compromise of Wayside/Onboard Systems"]
    persistent_compromise --> malicious_update
    attacker["[U01] Attacker"]
    attacker --> persistent_compromise
    physical_sabotage["[G05] Physical Sabotage or Tampering"]
    physical_sabotage --> root
    physical_assets["[A10] Physical Assets (Tracks, Power Lines, Cabinets)"]
    physical_assets --> physical_sabotage
    track_tampering["[H25] Tamper with Tracks (e.g., Remove Fishplates, Obstruct Sensors)"]
    track_tampering --> physical_assets
    derailment_risk["[H26] Create Derailment or Collision Risk"]
    derailment_risk --> track_tampering
    attacker["[U01] Attacker"]
    attacker --> derailment_risk
    power_sabotage["[H27] Sabotage Power Supply (e.g., Cut Cables, Overload Transformers)"]
    power_sabotage --> physical_assets
    system_shutdown["[H28] Force Emergency Shutdown of Wayside Systems"]
    system_shutdown --> power_sabotage
    attacker["[U01] Attacker"]
    attacker --> system_shutdown
    insider_threat["[G06] Insider Threat"]
    insider_threat --> root
    authorized_personnel["[A11] Authorized Personnel (Operators, Maintenance, Vendors)"]
    authorized_personnel --> insider_threat
    abuse_access["[V11] Abuse Legitimate Access for Malicious Actions"]
    abuse_access --> authorized_personnel
    disable_safety["[H29] Disable Safety Systems (e.g., ATP, Door Locks)"]
    disable_safety --> abuse_access
    unsafe_operation_insider["[H30] Enable Unsafe Train Operation"]
    unsafe_operation_insider --> disable_safety
    attacker["[U01] Attacker"]
    attacker --> unsafe_operation_insider
    data_exfiltration["[H31] Exfiltrate Sensitive Data (e.g., Cryptographic Keys, Timetables)"]
    data_exfiltration --> abuse_access
    future_attacks["[H32] Enable Future Targeted Attacks"]
    future_attacks --> data_exfiltration
    attacker["[U01] Attacker"]
    attacker --> future_attacks