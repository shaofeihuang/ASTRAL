graph BT
    root["[G01] Disrupt or Stop Cyber-Physical Operations of Tesla In-Vehicle Infotainment (IVI) System"]
    compromise_ivi_core["[G02] Compromise IVI Head Unit Core Functions"]
    compromise_ivi_core --> root
    exploit_os_kernel["[A01] Operating System Kernel"]
    exploit_os_kernel --> compromise_ivi_core
    kernel_vuln_priv_esc["[V01] Privilege Escalation via Kernel Exploit (e.g., CVE-2021-6543)"]
    kernel_vuln_priv_esc --> exploit_os_kernel
    unauth_code_exec["[G03] Execute Unauthorized Code with Elevated Privileges"]
    unauth_code_exec --> kernel_vuln_priv_esc
    disable_secure_boot["[H01] Disable Secure Boot Mechanism"]
    disable_secure_boot --> unauth_code_exec
    flash_malicious_firmware["[A02] Firmware Image"]
    flash_malicious_firmware --> disable_secure_boot
    attacker["[U01] Attacker"]
    attacker --> flash_malicious_firmware
    bypass_sandbox["[V02] Bypass App Sandboxing (e.g., via IPC Exploit)"]
    bypass_sandbox --> unauth_code_exec
    lateral_movement_to_ecus["[G04] Move Laterally to Safety-Critical ECUs"]
    lateral_movement_to_ecus --> bypass_sandbox
    can_bus_spoofing["[H02] Spoof CAN Bus Messages to ECUs"]
    can_bus_spoofing --> lateral_movement_to_ecus
    send_unauth_control_commands["[A03] CAN Bus Gateway"]
    send_unauth_control_commands --> can_bus_spoofing
    attacker["[U01] Attacker"]
    attacker --> send_unauth_control_commands
    kernel_dos["[V03] Kernel-Level Denial-of-Service (e.g., CVE-2019-5420)"]
    kernel_dos --> exploit_os_kernel
    system_crash["[H03] Crash IVI System via Resource Exhaustion"]
    system_crash --> kernel_dos
    attacker["[U01] Attacker"]
    attacker --> system_crash
    compromise_auth["[A04] Authentication & Cryptographic Modules"]
    compromise_auth --> compromise_ivi_core
    weak_tls_ota["[V04] Weak TLS Implementation in OTA Updates"]
    weak_tls_ota --> compromise_auth
    mitm_ota_hijack["[H04] MITM Attack to Deliver Malicious OTA Update"]
    mitm_ota_hijack --> weak_tls_ota
    rogue_update_server["[A05] Compromised OTA Update Server (Purdue L3.5)"]
    rogue_update_server --> mitm_ota_hijack
    attacker["[U01] Attacker"]
    attacker --> rogue_update_server
    hardcoded_creds["[V05] Hardcoded Service Credentials in Diagnostic Ports"]
    hardcoded_creds --> compromise_auth
    unauth_diag_access["[H05] Gain Unauthorized Access via OBD-II Port"]
    unauth_diag_access --> hardcoded_creds
    flash_ecu_via_diag["[A06] ECU Firmware via Diagnostic Tools"]
    flash_ecu_via_diag --> unauth_diag_access
    attacker["[U01] Attacker"]
    attacker --> flash_ecu_via_diag
    compromise_connectivity["[G05] Exploit Connectivity Interfaces for Unauthorized Access"]
    compromise_connectivity --> root
    cellular_wifi["[A07] Cellular/Wi-Fi Modem"]
    cellular_wifi --> compromise_connectivity
    rogue_base_station["[V06] Fake Cellular Base Station (e.g., Stingray)"]
    rogue_base_station --> cellular_wifi
    intercept_telemetry["[H06] Intercept/Modify Telemetry Data in Transit"]
    intercept_telemetry --> rogue_base_station
    spoof_cloud_commands["[A08] Tesla Cloud API (Purdue L3)"]
    spoof_cloud_commands --> intercept_telemetry
    attacker["[U01] Attacker"]
    attacker --> spoof_cloud_commands
    wifi_eap_downgrade["[V07] Wi-Fi EAP Downgrade Attack (e.g., to WEP)"]
    wifi_eap_downgrade --> cellular_wifi
    sniff_credentials["[H07] Capture Tesla Account Credentials"]
    sniff_credentials --> wifi_eap_downgrade
    unauth_cloud_access["[A09] Tesla Account Session (Purdue L3.5)"]
    unauth_cloud_access --> sniff_credentials
    attacker["[U01] Attacker"]
    attacker --> unauth_cloud_access
    bluetooth["[A10] Bluetooth Module"]
    bluetooth --> compromise_connectivity
    blueborne_exploit["[V08] BlueBorne Vulnerability (e.g., CVE-2017-1000251)"]
    blueborne_exploit --> bluetooth
    remote_code_exec["[H08] Execute Arbitrary Code via Bluetooth RCE"]
    remote_code_exec --> blueborne_exploit
    pairing_relay_attack["[A11] Phone-as-a-Key Proximity Authentication"]
    pairing_relay_attack --> remote_code_exec
    attacker["[U01] Attacker"]
    attacker --> pairing_relay_attack
    usb_ports["[A12] USB Ports"]
    usb_ports --> compromise_connectivity
    badusb["[V09] BadUSB Attack via Malicious Firmware"]
    badusb --> usb_ports
    emulate_hid["[H09] Emulate HID to Inject Keystrokes/Commands"]
    emulate_hid --> badusb
    usb_boot_exploit["[A13] USB Bootloader (e.g., U-Boot)"]
    usb_boot_exploit --> emulate_hid
    attacker["[U01] Attacker"]
    attacker --> usb_boot_exploit
    malicious_media["[V10] Malicious Media File Exploit (e.g., CVE-2020-12345)"]
    malicious_media --> usb_ports
    buffer_overflow["[H10] Trigger Buffer Overflow in Media Player"]
    buffer_overflow --> malicious_media
    code_exec_via_media["[A14] IVI Media Processing Library"]
    code_exec_via_media --> buffer_overflow
    attacker["[U01] Attacker"]
    attacker --> code_exec_via_media
    compromise_apps["[G06] Exploit Application Layer Vulnerabilities"]
    compromise_apps --> root
    third_party_app["[A15] Third-Party Application"]
    third_party_app --> compromise_apps
    app_ipc_exploit["[V11] Vulnerable IPC Mechanism (e.g., D-Bus)"]
    app_ipc_exploit --> third_party_app
    escalate_to_system["[H11] Escalate Privileges via IPC to System Level"]
    escalate_to_system --> app_ipc_exploit
    malicious_app_store["[A16] Compromised Tesla App Store (Supply Chain)"]
    malicious_app_store --> escalate_to_system
    attacker["[U01] Attacker"]
    attacker --> malicious_app_store
    web_browser["[A17] IVI Web Browser"]
    web_browser --> compromise_apps
    xss_driveby["[V12] Cross-Site Scripting (XSS) in Browser (e.g., CVE-2019-9810)"]
    xss_driveby --> web_browser
    browser_rce["[H12] Achieve Remote Code Execution via Browser Exploit"]
    browser_rce --> xss_driveby
    malicious_website["[A18] Hostile Website (e.g., via Wi-Fi Hotspot)"]
    malicious_website --> browser_rce
    attacker["[U01] Attacker"]
    attacker --> malicious_website
    voice_assistant["[A19] Voice Assistant"]
    voice_assistant --> compromise_apps
    voice_command_injection["[V13] Voice Command Injection (e.g., Hidden Voice Attacks)"]
    voice_command_injection --> voice_assistant
    unauth_vehicle_control["[H13] Issue Unauthorized Voice Commands to Vehicle Systems"]
    unauth_vehicle_control --> voice_command_injection
    ultrasonic_voice_spoofing["[A20] Ultrasonic or AI-Generated Voice Spoofing"]
    ultrasonic_voice_spoofing --> unauth_vehicle_control
    attacker["[U01] Attacker"]
    attacker --> ultrasonic_voice_spoofing
    compromise_hmi["[G07] Manipulate Human-Machine Interface (HMI) for Deception"]
    compromise_hmi --> root
    touchscreen_ui["[A21] Touchscreen UI"]
    touchscreen_ui --> compromise_hmi
    ui_spoofing["[V14] UI Spoofing (e.g., Overlay Attacks)"]
    ui_spoofing --> touchscreen_ui
    fake_auth_prompt["[H14] Display Fake Authentication Prompt to Capture Credentials"]
    fake_auth_prompt --> ui_spoofing
    social_engineering_driver["[A22] Driver or Passenger Interaction"]
    social_engineering_driver --> fake_auth_prompt
    attacker["[U01] Attacker"]
    attacker --> social_engineering_driver
    climate_control_ui["[A23] Climate Control UI"]
    climate_control_ui --> compromise_hmi
    fake_overheat_warning["[V15] Spoof Sensor Data to Trigger False Warnings"]
    fake_overheat_warning --> climate_control_ui
    panic_driver["[H15] Cause Driver Panic via False Critical Alerts"]
    panic_driver --> fake_overheat_warning
    can_sensor_spoofing["[A24] Spoofed CAN Bus Sensor Data"]
    can_sensor_spoofing --> panic_driver
    attacker["[U01] Attacker"]
    attacker --> can_sensor_spoofing
    compromise_gateways["[G08] Bypass Gateways to Access Safety-Critical Networks"]
    compromise_gateways --> root
    can_ethernet_gateway["[A25] CAN-Ethernet Gateway"]
    can_ethernet_gateway --> compromise_gateways
    gateway_auth_bypass["[V16] Bypass Gateway Authentication (e.g., Missing CAN FD Auth)"]
    gateway_auth_bypass --> can_ethernet_gateway
    inject_can_messages["[H16] Inject Unauthorized CAN Messages to ECUs"]
    inject_can_messages --> gateway_auth_bypass
    ecu_firmware_exploit["[A26] Vulnerable ECU Firmware (e.g., CVE-2019-10126)"]
    ecu_firmware_exploit --> inject_can_messages
    attacker["[U01] Attacker"]
    attacker --> ecu_firmware_exploit
    automotive_ethernet["[A27] Automotive Ethernet Switch"]
    automotive_ethernet --> compromise_gateways
    ethernet_vlan_hop["[V17] VLAN Hopping on Automotive Ethernet"]
    ethernet_vlan_hop --> automotive_ethernet
    access_adas_network["[H17] Gain Access to ADAS Network Segment"]
    access_adas_network --> ethernet_vlan_hop
    spoof_adas_sensor_data["[A28] ADAS Sensor Fusion Module"]
    spoof_adas_sensor_data --> access_adas_network
    attacker["[U01] Attacker"]
    attacker --> spoof_adas_sensor_data
    compromise_cloud["[G09] Exploit Cloud Services for Fleet-Wide Impact"]
    compromise_cloud --> root
    tesla_cloud_api["[A29] Tesla Cloud API (Purdue L3.5)"]
    tesla_cloud_api --> compromise_cloud
    api_auth_bypass["[V18] Bypass Cloud API Authentication (e.g., JWT Weakness)"]
    api_auth_bypass --> tesla_cloud_api
    issue_remote_commands["[H18] Issue Unauthorized Remote Commands to Fleet"]
    issue_remote_commands --> api_auth_bypass
    compromised_tesla_account["[A30] Stolen Tesla Account Credentials"]
    compromised_tesla_account --> issue_remote_commands
    attacker["[U01] Attacker"]
    attacker --> compromised_tesla_account
    ota_signing_key_leak["[V19] Leaked OTA Signing Keys"]
    ota_signing_key_leak --> tesla_cloud_api
    sign_malicious_firmware["[H19] Sign and Distribute Malicious Firmware Updates"]
    sign_malicious_firmware --> ota_signing_key_leak
    rogue_ota_server["[A31] Compromised CDN or Update Mirror"]
    rogue_ota_server --> sign_malicious_firmware
    attacker["[U01] Attacker"]
    attacker --> rogue_ota_server
    telemetry_db["[A32] Telemetry Database (Purdue L3)"]
    telemetry_db --> compromise_cloud
    telemetry_tampering["[V20] Tamper with Stored Telemetry Data"]
    telemetry_tampering --> telemetry_db
    fake_vehicle_health["[H20] Inject False Vehicle Health Data for Fleet Analytics"]
    fake_vehicle_health --> telemetry_tampering
    insider_db_access["[A33] Compromised Tesla Employee Credentials"]
    insider_db_access --> fake_vehicle_health
    attacker["[U01] Attacker"]
    attacker --> insider_db_access
    supply_chain_attack["[G10] Compromise Supply Chain for Persistent Access"]
    supply_chain_attack --> root
    oem_firmware["[A34] OEM-Supplied Firmware (e.g., Infotainment Chipset)"]
    oem_firmware --> supply_chain_attack
    backdoor_in_firmware["[V21] Pre-Installed Backdoor in Firmware"]
    backdoor_in_firmware --> oem_firmware
    persistent_rootkit["[H21] Deploy Persistent Rootkit in IVI System"]
    persistent_rootkit --> backdoor_in_firmware
    compromised_oem_vendor["[A35] Malicious OEM Vendor or Insider"]
    compromised_oem_vendor --> persistent_rootkit
    attacker["[U01] Attacker"]
    attacker --> compromised_oem_vendor
    third_party_sdk["[A36] Third-Party SDK in Tesla Apps"]
    third_party_sdk --> supply_chain_attack
    vulnerable_sdk["[V22] Vulnerable SDK with Known Exploits"]
    vulnerable_sdk --> third_party_sdk
    sdk_rce["[H22] Exploit SDK Vulnerability for Code Execution"]
    sdk_rce --> vulnerable_sdk
    malicious_sdk_provider["[A37] Compromised SDK Provider"]
    malicious_sdk_provider --> sdk_rce
    attacker["[U01] Attacker"]
    attacker --> malicious_sdk_provider
    physical_attack["[G11] Physical Tampering with IVI or Vehicle Systems"]
    physical_attack --> root
    diagnostic_port["[A38] OBD-II or Proprietary Diagnostic Port"]
    diagnostic_port --> physical_attack
    unlocked_diag_port["[V23] Unlocked or Weakly Secured Diagnostic Port"]
    unlocked_diag_port --> diagnostic_port
    flash_ecu_via_obd["[H23] Flash Malicious ECU Firmware via OBD-II"]
    flash_ecu_via_obd --> unlocked_diag_port
    physical_access_to_vehicle["[A39] Unsupervised Vehicle Access"]
    physical_access_to_vehicle --> flash_ecu_via_obd
    attacker["[U01] Attacker"]
    attacker --> physical_access_to_vehicle
    ivi_hardware["[A40] IVI Hardware (e.g., NVIDIA Tegra Chip)"]
    ivi_hardware --> physical_attack
    jtag_debug_exploit["[V24] Exposed JTAG or Debug Interfaces"]
    jtag_debug_exploit --> ivi_hardware
    dump_extract_firmware["[H24] Dump and Reverse Engineer Firmware"]
    dump_extract_firmware --> jtag_debug_exploit
    physical_dismantling["[A41] Physical Dismantling of IVI Unit"]
    physical_dismantling --> dump_extract_firmware
    attacker["[U01] Attacker"]
    attacker --> physical_dismantling
    social_engineering["[G12] Social Engineering Attacks Targeting Users or Technicians"]
    social_engineering --> root
    tesla_account["[A42] Tesla Account Credentials"]
    tesla_account --> social_engineering
    phishing_attack["[V25] Phishing for Tesla Account Credentials"]
    phishing_attack --> tesla_account
    account_takeover["[H25] Take Over Tesla Account for Remote Access"]
    account_takeover --> phishing_attack
    fake_tesla_email["[A43] Spoofed Tesla Support Email"]
    fake_tesla_email --> account_takeover
    attacker["[U01] Attacker"]
    attacker --> fake_tesla_email
    service_technician["[A44] Service Technician Credentials"]
    service_technician --> social_engineering
    impersonate_technician["[V26] Impersonate Service Technician (e.g., via Stolen Uniform/Badge)"]
    impersonate_technician --> service_technician
    unauth_service_access["[H26] Gain Unauthorized Access to Service Mode"]
    unauth_service_access --> impersonate_technician
    fake_service_appointment["[A45] Socially Engineered Service Appointment"]
    fake_service_appointment --> unauth_service_access
    attacker["[U01] Attacker"]
    attacker --> fake_service_appointment