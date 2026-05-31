graph BT
    root["[G01] Cyber-Physical System (CPS) Disruption in Healthcare Environment"]
    spoof_medical_device["[H01] Spoofing of Legitimate Medical Devices"]
    spoof_medical_device --> root
    infusion_pump_spoof["[A01] Infusion Pump (MedFusion 3000) Authentication Bypass"]
    infusion_pump_spoof --> spoof_medical_device
    cve_2022_1234["[V01] Exploit CVE-2022-1234 (Weak Device Authentication Protocol)"]
    cve_2022_1234 --> infusion_pump_spoof
    wilddraw_campaign["[H02] WildDraw Campaign Exploitation Framework"]
    wilddraw_campaign --> cve_2022_1234
    attacker["[U01] Attacker"]
    attacker --> wilddraw_campaign
    protocol_weakness["[V02] Exploitable Weakness in Medical Device Communication Protocol (e.g., DICOM, HL7)"]
    protocol_weakness --> spoof_medical_device
    mitm_spoofing["[H03] Man-in-the-Middle (MITM) Spoofing Attack"]
    mitm_spoofing --> protocol_weakness
    attacker --> mitm_spoofing
    tamper_device_config["[H04] Tampering with Medical Device Configuration"]
    tamper_device_config --> root
    radiology_system_tamper["[A02] Radiology Imaging System (RadiologyXpert 5000) Configuration"]
    radiology_system_tamper --> tamper_device_config
    cve_2023_5678["[V03] Exploit CVE-2023-5678 (Unauthorized Configuration Changes)"]
    cve_2023_5678 --> radiology_system_tamper
    darkmed_campaign["[H05] DarkMed Campaign Tampering Framework"]
    darkmed_campaign --> cve_2023_5678
    attacker --> darkmed_campaign
    firmware_tamper["[A03] Medical Device Firmware (e.g., PLC, Embedded Controller)"]
    firmware_tamper --> tamper_device_config
    unsecured_update_mechanism["[V04] Unsecured Firmware Update Mechanism (e.g., TFTP, HTTP)"]
    unsecured_update_mechanism --> firmware_tamper
    malicious_firmware_injection["[H06] Injection of Malicious Firmware via Supply Chain or Local Access"]
    malicious_firmware_injection --> unsecured_update_mechanism
    attacker --> malicious_firmware_injection
    repudiation_attacks["[H07] Repudiation Attacks (Log Tampering/Evasion)"]
    repudiation_attacks --> root
    audit_log_weakness["[A04] Audit Logging System (e.g., SIEM, Local Device Logs)"]
    audit_log_weakness --> repudiation_attacks
    insufficient_logging["[V05] Insufficient Logging and Monitoring Capabilities"]
    insufficient_logging --> audit_log_weakness
    log_deletion["[H08] Deletion or Alteration of Log Files"]
    log_deletion --> insufficient_logging
    attacker --> log_deletion
    timestomping["[H09] Timestomping or Log Injection via Compromised Credentials"]
    timestomping --> repudiation_attacks
    compromised_admin_creds["[V06] Compromised Administrative Credentials (e.g., Default/Weak Passwords)"]
    compromised_admin_creds --> timestomping
    attacker --> compromised_admin_creds
    information_disclosure["[H10] Unauthorized Information Disclosure (Data Breach)"]
    information_disclosure --> root
    patient_data_transmission["[A05] Patient Data Transmission (e.g., EHR to Medical Device)"]
    patient_data_transmission --> information_disclosure
    cve_2021_9012["[V07] Exploit CVE-2021-9012 (Unencrypted Data Transmission)"]
    cve_2021_9012 --> patient_data_transmission
    silentsnoop_eavesdropping["[H11] SilentSnoop Campaign Eavesdropping Framework"]
    silentsnoop_eavesdropping --> cve_2021_9012
    attacker --> silentsnoop_eavesdropping
    unsecured_api_endpoint["[A06] Unsecured Cloud API Endpoint (e.g., FHIR/HL7 Gateway)"]
    unsecured_api_endpoint --> information_disclosure
    excessive_data_exposure["[V08] Excessive Data Exposure via Misconfigured API Permissions"]
    excessive_data_exposure --> unsecured_api_endpoint
    api_data_exfiltration["[H12] Automated Exfiltration of Sensitive Data via API Abuse"]
    api_data_exfiltration --> excessive_data_exposure
    attacker --> api_data_exfiltration
    denial_of_service["[H13] Denial-of-Service (DoS) Against Critical Medical Systems"]
    denial_of_service --> root
    lifesupport_device_dos["[A07] Life-Support Device (LifeSupport 4000) Network Interface"]
    lifesupport_device_dos --> denial_of_service
    cve_2022_3456["[V09] Exploit CVE-2022-3456 (Device Communication Protocol Flooding)"]
    cve_2022_3456 --> lifesupport_device_dos
    crashoverload_attack["[H14] CrashOverload Campaign DoS Framework"]
    crashoverload_attack --> cve_2022_3456
    attacker --> crashoverload_attack
    network_infrastructure_dos["[A08] Network Infrastructure (e.g., Routers, Switches)"]
    network_infrastructure_dos --> denial_of_service
    unpatched_network_devices["[V10] Unpatched Network Devices Vulnerable to DoS (e.g., Cisco, Juniper CVEs)"]
    unpatched_network_devices --> network_infrastructure_dos
    network_flooding["[H15] SYN Flood or ICMP Flood Attack on Critical Segments"]
    network_flooding --> unpatched_network_devices
    attacker --> network_flooding
    privilege_escalation["[H16] Privilege Escalation in Medical CPS"]
    privilege_escalation --> root
    user_management_system["[A09] User Management System (MedAdmin Pro)"]
    user_management_system --> privilege_escalation
    cve_2023_7890["[V11] Exploit CVE-2023-7890 (Privilege Escalation Vulnerability)"]
    cve_2023_7890 --> user_management_system
    privesc_campaign["[H17] PrivEsc Campaign Exploitation Framework"]
    privesc_campaign --> cve_2023_7890
    attacker --> privesc_campaign
    misconfigured_access_controls["[V12] Misconfigured Access Controls (e.g., Over-Permissive RBAC)"]
    misconfigured_access_controls --> privilege_escalation
    lateral_priv_esc["[H18] Lateral Movement with Escalated Privileges"]
    lateral_priv_esc --> misconfigured_access_controls
    attacker --> lateral_priv_esc
    lateral_movement["[H19] Lateral Movement Across Medical CPS Zones"]
    lateral_movement --> root
    weak_network_segmentation["[V13] Weak Network Segmentation (e.g., Flat VLAN, Missing Firewall Rules)"]
    weak_network_segmentation --> lateral_movement
    pivot_from_low_security_device["[H20] Pivot from Compromised Low-Security Device (e.g., Printer, IoT Sensor)"]
    pivot_from_low_security_device --> weak_network_segmentation
    attacker --> pivot_from_low_security_device
    shared_credentials["[A10] Shared or Default Credentials Across Devices"]
    shared_credentials --> lateral_movement
    credential_reuse_attack["[H21] Credential Reuse Attack for Lateral Movement"]
    credential_reuse_attack --> shared_credentials
    attacker --> credential_reuse_attack
    supply_chain_compromise["[H22] Supply Chain Compromise (Hardware/Firmware Tampering)"]
    supply_chain_compromise --> root
    third_party_firmware["[A11] Third-Party Firmware or Software Updates"]
    third_party_firmware --> supply_chain_compromise
    malicious_vendor_update["[V14] Malicious or Backdoored Vendor Update (e.g., SolarWinds-style Attack)"]
    malicious_vendor_update --> third_party_firmware
    supply_chain_attack_vector["[H23] Compromised Update Server or CDN Hijacking"]
    supply_chain_attack_vector --> malicious_vendor_update
    attacker --> supply_chain_attack_vector
    counterfeit_hardware["[A12] Counterfeit or Tampered Hardware (e.g., PLCs, Medical Devices)"]
    counterfeit_hardware --> supply_chain_compromise
    hardware_backdoor["[V15] Hardware-Level Backdoor (e.g., FPGA Trojan, BIOS Implant)"]
    hardware_backdoor --> counterfeit_hardware
    physical_tampering["[H24] Physical Tampering During Shipping or Maintenance"]
    physical_tampering --> hardware_backdoor
    attacker --> physical_tampering
    ai_ml_manipulation["[H25] AI/ML Model Manipulation (Poisoning/Evasion)"]
    ai_ml_manipulation --> root
    ai_training_data["[A13] AI Training Data (e.g., Historian, EHR Datasets)"]
    ai_training_data --> ai_ml_manipulation
    data_poisoning["[V16] Adversarial Data Poisoning in Training Pipeline"]
    data_poisoning --> ai_training_data
    ai_model_compromise["[H26] Compromised AI Model Leading to Misdiagnosis"]
    ai_model_compromise --> data_poisoning
    attacker --> ai_model_compromise
    ai_inference_evade["[A14] AI Inference Engine (e.g., Predictive Diagnostics Model)"]
    ai_inference_evade --> ai_ml_manipulation
    adversarial_input["[V17] Adversarial Inputs to Evasion Attack (e.g., Perturbed Sensor Data)"]
    adversarial_input --> ai_inference_evade
    false_negative_exploitation["[H27] Exploitation of False Negatives in Critical Alerts"]
    false_negative_exploitation --> adversarial_input
    attacker --> false_negative_exploitation
    physical_intrusion["[H28] Physical Intrusion and Direct Tampering"]
    physical_intrusion --> root
    unsecured_physical_access["[A15] Unsecured Physical Access Points (e.g., Network Jacks, USB Ports)"]
    unsecured_physical_access --> physical_intrusion
    usb_based_attack["[V18] USB-Based Attack (e.g., BadUSB, Rubber Ducky)"]
    usb_based_attack --> unsecured_physical_access
    local_device_compromise["[H29] Local Compromise of Medical Device or HMI"]
    local_device_compromise --> usb_based_attack
    attacker --> local_device_compromise
    biometric_bypass["[A16] Biometric or Physical Access Control System"]
    biometric_bypass --> physical_intrusion
    access_control_exploit["[V19] Exploit in Physical Access Control (e.g., RFID Cloning, Tailgating)"]
    access_control_exploit --> biometric_bypass
    unauthorized_physical_access["[H30] Unauthorized Access to Restricted Areas (e.g., Server Rooms, Device Closets)"]
    unauthorized_physical_access --> access_control_exploit
    attacker --> unauthorized_physical_access
    social_engineering["[H31] Social Engineering and Insider Threats"]
    social_engineering --> root
    clinical_staff_targeting["[A17] Clinical Staff (e.g., Nurses, Technicians)"]
    clinical_staff_targeting --> social_engineering
    phishing_attack["[V20] Phishing or Spear-Phishing Attack (e.g., Credential Harvesting)"]
    phishing_attack --> clinical_staff_targeting
    compromised_credentials["[H32] Compromised Credentials for EHR or Medical Device Access"]
    compromised_credentials --> phishing_attack
    attacker --> compromised_credentials
    maintenance_personnel["[A18] Maintenance or Vendor Support Personnel"]
    maintenance_personnel --> social_engineering
    fake_patch_request["[V21] Fake 'Urgent Patch' or 'Maintenance' Request"]
    fake_patch_request --> maintenance_personnel
    malicious_on_site_action["[H33] On-Site Execution of Malicious Actions (e.g., Firmware Flashing)"]
    malicious_on_site_action --> fake_patch_request
    attacker --> malicious_on_site_action