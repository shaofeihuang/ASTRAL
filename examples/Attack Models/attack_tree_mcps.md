graph BT
    root["[G00] Disrupt or Stop Cyber-Physical System Operations in Medical Environment"]
    spoof_goal["[G01] Achieve Spoofing of Legitimate Devices/Commands"]
    spoof_goal --> root
    asset_network["[A01] Network Infrastructure (IT/OT Convergence)"]
    asset_network --> spoof_goal
    vul_auth_weak["[V01] Weak or Missing Authentication in Device Protocols (e.g., HL7, DICOM)"]
    vul_auth_weak --> asset_network
    asset_med_device["[A02] Medical Devices (e.g., Infusion Pumps, Ventilators)"]
    asset_med_device --> vul_auth_weak
    haz_false_data["[H01] Injection of False Patient Vitals or Device Commands"]
    haz_false_data --> asset_med_device
    attacker["[U01] Attacker"]
    attacker --> haz_false_data
    vul_proto_spoof["[V02] Protocol Spoofing (e.g., Modbus, BACnet) Due to Lack of Cryptographic Validation"]
    vul_proto_spoof --> asset_network
    asset_gateway["[A03] Protocol Gateway Devices (IT ↔ OT Translation)"]
    asset_gateway --> vul_proto_spoof
    haz_control_hijack["[H02] Hijacking of Control Commands to Actuators (e.g., Drug Dosage, Surgical Robots)"]
    haz_control_hijack --> asset_gateway
    attacker["[U01] Attacker"]
    attacker --> haz_control_hijack
    asset_wireless["[A04] Wireless Access Points (Wi-Fi, BLE, Zigbee)"]
    asset_wireless --> spoof_goal
    vul_rogue_ap["[V03] Rogue Access Point Spoofing (e.g., Evil Twin Attack on Medical IoT)"]
    vul_rogue_ap --> asset_wireless
    asset_sensor["[A05] Wireless Sensors (e.g., ECG, SpO2 Monitors)"]
    asset_sensor --> vul_rogue_ap
    haz_false_telemetry["[H03] Spoofed Telemetry Data Leading to Misdiagnosis"]
    haz_false_telemetry --> asset_sensor
    attacker["[U01] Attacker"]
    attacker --> haz_false_telemetry
    tamper_goal["[G02] Tamper with Device Configurations or Patient Data"]
    tamper_goal --> root
    asset_ehr["[A06] Electronic Health Record (EHR) Systems"]
    asset_ehr --> tamper_goal
    vul_input_val["[V04] Lack of Input Validation in Patient Data Fields (e.g., Dosage Parameters)"]
    vul_input_val --> asset_ehr
    haz_incorrect_rx["[H04] Altered Prescription Data Causing Overdose/Underdose"]
    haz_incorrect_rx --> vul_input_val
    attacker["[U01] Attacker"]
    attacker --> haz_incorrect_rx
    vul_inject_sql["[V05] SQL Injection in EHR Database Queries"]
    vul_inject_sql --> asset_ehr
    asset_patient_db["[A07] Patient Database (PHI Storage)"]
    asset_patient_db --> vul_inject_sql
    haz_data_corrupt["[H05] Corruption or Deletion of Critical Patient Records"]
    haz_data_corrupt --> asset_patient_db
    attacker["[U01] Attacker"]
    attacker --> haz_data_corrupt
    asset_firmware["[A08] Firmware Update Mechanisms (OTA, Vendor Portals)"]
    asset_firmware --> tamper_goal
    vul_unauth_update["[V06] Unauthenticated Firmware Upload (e.g., CVE-2019-10974)"]
    vul_unauth_update --> asset_firmware
    asset_embedded_ctrl["[A09] Embedded Controllers (PLC-like Logic in Devices)"]
    asset_embedded_ctrl --> vul_unauth_update
    haz_malicious_fw["[H06] Malicious Firmware Leading to Device Brick or Malfunction"]
    haz_malicious_fw --> asset_embedded_ctrl
    attacker["[U01] Attacker"]
    attacker --> haz_malicious_fw
    vul_mitm_update["[V07] MITM on Firmware Download (e.g., Compromised Vendor Server or DNS Spoofing)"]
    vul_mitm_update --> asset_firmware
    haz_backdoor_install["[H07] Installation of Persistent Backdoor in Device Firmware"]
    haz_backdoor_install --> vul_mitm_update
    attacker["[U01] Attacker"]
    attacker --> haz_backdoor_install
    repud_goal["[G03] Perform Actions Without Traceability (Repudiation)"]
    repud_goal --> root
    asset_iam["[A10] Identity and Access Management (IAM) Systems"]
    asset_iam --> repud_goal
    vul_log_tamper["[V08] Insufficient Logging or Log Tampering (e.g., Disabled Audit Trails)"]
    vul_log_tamper --> asset_iam
    asset_admin_workstation["[A11] Administrative Workstations (Configuration/Management)"]
    asset_admin_workstation --> vul_log_tamper
    haz_untraceable_actions["[H08] Unauthorized Configuration Changes Without Attribution"]
    haz_untraceable_actions --> asset_admin_workstation
    attacker["[U01] Attacker"]
    attacker --> haz_untraceable_actions
    asset_siem["[A12] SIEM/Centralized Logging Systems"]
    asset_siem --> repud_goal
    vul_time_spoof["[V09] NTP Spoofing to Disrupt Event Timestamps"]
    vul_time_spoof --> asset_siem
    haz_event_obfuscation["[H09] Obfuscation of Attack Timeline in Logs"]
    haz_event_obfuscation --> vul_time_spoof
    attacker["[U01] Attacker"]
    attacker --> haz_event_obfuscation
    info_disc_goal["[G04] Exfiltrate Sensitive Patient or Device Data"]
    info_disc_goal --> root
    asset_network_traffic["[A13] Unencrypted Network Traffic (IT ↔ OT)"]
    asset_network_traffic --> info_disc_goal
    vul_sniffing["[V10] Passive Sniffing of Cleartext Protocols (e.g., HL7v2, Modbus)"]
    vul_sniffing --> asset_network_traffic
    asset_phi_data["[A14] Patient Health Information (PHI) in Transit"]
    asset_phi_data --> vul_sniffing
    haz_data_leak["[H10] Exfiltration of PHI to External Servers"]
    haz_data_leak --> asset_phi_data
    attacker["[U01] Attacker"]
    attacker --> haz_data_leak
    asset_cloud_sync["[A15] Cloud-Synchronized Devices (e.g., Remote Diagnostics)"]
    asset_cloud_sync --> info_disc_goal
    vul_misconfig_storage["[V11] Misconfigured Cloud Storage (e.g., Public S3 Buckets)"]
    vul_misconfig_storage --> asset_cloud_sync
    asset_device_backups["[A16] Device Configuration Backups (e.g., Therapy Parameters)"]
    asset_device_backups --> vul_misconfig_storage
    haz_config_leak["[H11] Exposure of Sensitive Device Configurations"]
    haz_config_leak --> asset_device_backups
    attacker["[U01] Attacker"]
    attacker --> haz_config_leak
    dos_goal["[G05] Disrupt Availability of Critical Systems (DoS)"]
    dos_goal --> root
    asset_hmi["[A17] Human-Machine Interfaces (HMIs)"]
    asset_hmi --> dos_goal
    vul_flooding["[V12] UDP/TCP Flooding on HMI-Device Communication (e.g., Modbus TCP)"]
    vul_flooding --> asset_hmi
    haz_device_unresponsive["[H12] Unresponsive Critical Devices (e.g., Ventilators, Infusion Pumps)"]
    haz_device_unresponsive --> vul_flooding
    attacker["[U01] Attacker"]
    attacker --> haz_device_unresponsive
    asset_wireless_jammer["[A18] Wireless Spectrum (2.4GHz, ISM Bands)"]
    asset_wireless_jammer --> dos_goal
    vul_jamming["[V13] RF Jamming of Wireless Medical Devices (e.g., BLE, Zigbee)"]
    vul_jamming --> asset_wireless_jammer
    haz_sensor_dropout["[H13] Loss of Telemetry from Wireless Sensors (e.g., ECG, SpO2)"]
    haz_sensor_dropout --> vul_jamming
    attacker["[U01] Attacker"]
    attacker --> haz_sensor_dropout
    asset_ntp["[A19] NTP Servers (Time Synchronization)"]
    asset_ntp --> dos_goal
    vul_ntp_amplification["[V14] NTP Amplification Attack on OT Network"]
    vul_ntp_amplification --> asset_ntp
    haz_time_desync["[H14] Desynchronized Device Clocks Causing Event Correlation Failures"]
    haz_time_desync --> vul_ntp_amplification
    attacker["[U01] Attacker"]
    attacker --> haz_time_desync
    eop_goal["[G06] Elevate Privileges to Gain Unauthorized Control"]
    eop_goal --> root
    asset_iam_weak["[A20] IAM Systems with Default/Misconfigured RBAC"]
    asset_iam_weak --> eop_goal
    vul_priv_esc["[V15] Privilege Escalation via Exploitable Services (e.g., CVE-2019-10974)"]
    vul_priv_esc --> asset_iam_weak
    asset_admin_console["[A21] Administrative Consoles (Device Management)"]
    asset_admin_console --> vul_priv_esc
    haz_full_device_control["[H15] Unauthorized Administrative Access to Critical Devices"]
    haz_full_device_control --> asset_admin_console
    attacker["[U01] Attacker"]
    attacker --> haz_full_device_control
    asset_shared_creds["[A22] Shared or Hardcoded Credentials in Medical Devices"]
    asset_shared_creds --> eop_goal
    vul_cred_reuse["[V16] Credential Reuse Across Devices (e.g., Default Manufacturer Passwords)"]
    vul_cred_reuse --> asset_shared_creds
    haz_lateral_movement["[H16] Lateral Movement Across Compromised Devices"]
    haz_lateral_movement --> vul_cred_reuse
    attacker["[U01] Attacker"]
    attacker --> haz_lateral_movement
    lateral_goal["[G07] Move Laterally Across Network Segments"]
    lateral_goal --> root
    asset_segmentation["[A23] Poorly Segmented IT/OT Network"]
    asset_segmentation --> lateral_goal
    vul_flat_network["[V17] Flat Network Architecture (No Micro-Segmentation)"]
    vul_flat_network --> asset_segmentation
    asset_vpn_gateway["[A24] VPN Gateways (Remote Access)"]
    asset_vpn_gateway --> vul_flat_network
    haz_ot_from_it["[H17] Pivot from IT to OT via Compromised VPN or Jump Host"]
    haz_ot_from_it --> asset_vpn_gateway
    attacker["[U01] Attacker"]
    attacker --> haz_ot_from_it
    asset_trust_relationship["[A25] Implicit Trust Relationships Between Devices"]
    asset_trust_relationship --> lateral_goal
    vul_trust_exploit["[V18] Exploitation of Trusted Device Communication (e.g., HL7 Auto-Forwarding)"]
    vul_trust_exploit --> asset_trust_relationship
    haz_auto_propagation["[H18] Automatic Propagation of Malware via Trusted Channels"]
    haz_auto_propagation --> vul_trust_exploit
    attacker["[U01] Attacker"]
    attacker --> haz_auto_propagation
    physical_goal["[G08] Exploit Physical Access to Compromise Systems"]
    physical_goal --> root
    asset_usb_ports["[A26] Unsecured USB/Serial Ports on Medical Devices"]
    asset_usb_ports --> physical_goal
    vul_usb_exploit["[V19] USB-Based Exploitation (e.g., BadUSB, Rubber Ducky)"]
    vul_usb_exploit --> asset_usb_ports
    haz_firmware_flash["[H19] Unauthorized Firmware Flashing via Physical Ports"]
    haz_firmware_flash --> vul_usb_exploit
    attacker["[U01] Attacker"]
    attacker --> haz_firmware_flash
    asset_maintenance_mode["[A27] Maintenance Mode Interfaces (e.g., JTAG, UART)"]
    asset_maintenance_mode --> physical_goal
    vul_debug_access["[V20] Unprotected Debug/Service Modes (e.g., Manufacturer Backdoors)"]
    vul_debug_access --> asset_maintenance_mode
    haz_bypass_auth["[H20] Bypass of Authentication via Maintenance Ports"]
    haz_bypass_auth --> vul_debug_access
    attacker["[U01] Attacker"]
    attacker --> haz_bypass_auth
    supply_chain_goal["[G09] Compromise via Supply Chain or Third-Party Vectors"]
    supply_chain_goal --> root
    asset_vendor_portal["[A28] Vendor Update Portals (Firmware/Patch Distribution)"]
    asset_vendor_portal --> supply_chain_goal
    vul_vendor_compromise["[V21] Compromised Vendor Systems (e.g., SolarWinds-style Attack)"]
    vul_vendor_compromise --> asset_vendor_portal
    haz_malicious_updates["[H21] Distribution of Malicious Updates to Devices"]
    haz_malicious_updates --> vul_vendor_compromise
    attacker["[U01] Attacker"]
    attacker --> haz_malicious_updates
    asset_third_party["[A29] Third-Party Integrators (Remote Support Access)"]
    asset_third_party --> supply_chain_goal
    vul_remote_tool["[V22] Exploitable Remote Support Tools (e.g., TeamViewer, RDP)"]
    vul_remote_tool --> asset_third_party
    haz_persistent_access["[H22] Persistent Access via Legitimate Remote Support Channels"]
    haz_persistent_access --> vul_remote_tool
    attacker["[U01] Attacker"]
    attacker --> haz_persistent_access