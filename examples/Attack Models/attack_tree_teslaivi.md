graph BT
    root["[G01] CPS Disruption: Compromise Tesla In-Vehicle Infotainment (IVI) System Operations"]
    spoofing_root["[H01] Spoofing Attacks on IVI System"]
    spoofing_root --> root
    spoofing_diag["[H02] Spoof Diagnostic Requests via Cellular/Wi-Fi Interfaces"]
    spoofing_diag --> spoofing_root
    vul_diag_auth["[V01] Weak Authentication in Tesla IVI External Communication Protocols"]
    vul_diag_auth --> spoofing_diag
    asset_cellular_modem["[A01] Cellular Modem (4G/5G) in Telematics Control Unit (TCU)"]
    asset_cellular_modem --> vul_diag_auth
    attacker["[U01] Attacker"]
    attacker --> asset_cellular_modem
    spoofing_bluetooth["[H03] Spoof Paired Mobile Device via Bluetooth Exploits"]
    spoofing_bluetooth --> spoofing_root
    vul_bluetooth_pairing["[V02] Bluetooth Pairing Process Vulnerabilities (e.g., BlueBorne)"]
    vul_bluetooth_pairing --> spoofing_bluetooth
    asset_bluetooth_stack["[A02] Bluetooth Stack in IVI Head Unit"]
    asset_bluetooth_stack --> vul_bluetooth_pairing
    attacker --> asset_bluetooth_stack
    tampering_root["[H04] Tampering with IVI System Components"]
    tampering_root --> root
    tampering_firmware_obd["[H05] Tamper with Firmware via OBD-II Port Access"]
    tampering_firmware_obd --> tampering_root
    vul_firmware_update["[V03] Unsecured Firmware Update Process via OBD-II"]
    vul_firmware_update --> tampering_firmware_obd
    asset_obd_ii_port["[A03] OBD-II Diagnostic Port"]
    asset_obd_ii_port --> vul_firmware_update
    attacker --> asset_obd_ii_port
    tampering_js_injection["[H06] Inject Malicious JavaScript via IVI Web Browser"]
    tampering_js_injection --> tampering_root
    vul_browser_engine["[V04] Memory Corruption in IVI Web Browser Engine"]
    vul_browser_engine --> tampering_js_injection
    asset_ivi_browser["[A04] Web Browser in IVI Head Unit"]
    asset_ivi_browser --> vul_browser_engine
    attacker --> asset_ivi_browser
    repudiation_root["[H07] Repudiation: Undetected Malicious Actions"]
    repudiation_root --> root
    repudiation_can_spoofing["[H08] Spoof CAN Bus Messages Without Logging"]
    repudiation_can_spoofing --> repudiation_root
    vul_can_logging["[V05] Insufficient Logging of CAN Bus Messages"]
    vul_can_logging --> repudiation_can_spoofing
    asset_can_bus_interface["[A05] CAN Bus Interface in IVI Head Unit"]
    asset_can_bus_interface --> vul_can_logging
    attacker --> asset_can_bus_interface
    info_disclosure_root["[H09] Information Disclosure from IVI System"]
    info_disclosure_root --> root
    info_disclosure_can_eavesdrop["[H10] Eavesdrop on CAN Bus Messages via Cellular/Wi-Fi"]
    info_disclosure_can_eavesdrop --> info_disclosure_root
    vul_can_protocol["[V06] Unencrypted CAN Bus Message Transmission"]
    vul_can_protocol --> info_disclosure_can_eavesdrop
    asset_cellular_wifi_interface["[A06] Cellular/Wi-Fi Interface in TCU"]
    asset_cellular_wifi_interface --> vul_can_protocol
    attacker --> asset_cellular_wifi_interface
    info_disclosure_browser_exploit["[H11] Exfiltrate User Data via IVI Browser Exploit"]
    info_disclosure_browser_exploit --> info_disclosure_root
    vul_browser_sandbox["[V07] Inadequate Sandboxing in IVI Browser"]
    vul_browser_sandbox --> info_disclosure_browser_exploit
    asset_user_data_storage["[A07] User Data Storage (Contacts, Navigation History)"]
    asset_user_data_storage --> vul_browser_sandbox
    attacker --> asset_user_data_storage
    dos_root["[H12] Denial of Service (DoS) on IVI System"]
    dos_root --> root
    dos_can_flood["[H13] Flood IVI with Malicious CAN Messages"]
    dos_can_flood --> dos_root
    vul_can_protocol_dos["[V08] Lack of Rate Limiting in CAN Message Processing"]
    vul_can_protocol_dos --> dos_can_flood
    asset_can_bus_gateway["[A08] CAN Bus Gateway in IVI Head Unit"]
    asset_can_bus_gateway --> vul_can_protocol_dos
    attacker --> asset_can_bus_gateway
    dos_browser_crash["[H14] Crash IVI Browser via Malicious JavaScript"]
    dos_browser_crash --> dos_root
    vul_browser_dos["[V09] Unhandled Exceptions in Browser Rendering Engine"]
    vul_browser_dos --> dos_browser_crash
    asset_ivi_browser_engine["[A09] Browser Engine in IVI Head Unit"]
    asset_ivi_browser_engine --> vul_browser_dos
    attacker --> asset_ivi_browser_engine
    priv_esc_root["[H15] Elevation of Privilege in IVI System"]
    priv_esc_root --> root
    priv_esc_can_exploit["[H16] Exploit CAN Message Handling for Privilege Escalation"]
    priv_esc_can_exploit --> priv_esc_root
    vul_can_priv_esc["[V10] Improper Input Validation in CAN Message Parser"]
    vul_can_priv_esc --> priv_esc_can_exploit
    asset_can_message_handler["[A10] CAN Message Handler in IVI Firmware"]
    asset_can_message_handler --> vul_can_priv_esc
    attacker --> asset_can_message_handler
    lateral_movement_root["[H17] Lateral Movement from IVI to Other Vehicle Systems"]
    lateral_movement_root --> root
    lateral_movement_telematics["[H18] Pivot from IVI to Telematics Control Unit (TCU)"]
    lateral_movement_telematics --> lateral_movement_root
    vul_ivi_tcu_interface["[V11] Insecure IPC Between IVI and TCU"]
    vul_ivi_tcu_interface --> lateral_movement_telematics
    asset_ivi_tcu_communication["[A11] Communication Channel Between IVI and TCU"]
    asset_ivi_tcu_communication --> vul_ivi_tcu_interface
    attacker --> asset_ivi_tcu_communication
    lateral_movement_safety["[H19] Pivot from IVI to Safety-Critical ECUs"]
    lateral_movement_safety --> lateral_movement_root
    vul_ivi_ecu_seg["[V12] Inadequate Network Segmentation Between IVI and ECUs"]
    vul_ivi_ecu_seg --> lateral_movement_safety
    asset_ecu_gateway["[A12] Gateway Between IVI Ethernet and CAN FD Bus"]
    asset_ecu_gateway --> vul_ivi_ecu_seg
    attacker --> asset_ecu_gateway
    supply_chain_root["[H20] Supply Chain Compromise of IVI System"]
    supply_chain_root --> root
    supply_chain_ota["[H21] Deliver Malicious Payload via Compromised OTA Update"]
    supply_chain_ota --> supply_chain_root
    vul_ota_verification["[V13] Weak Cryptographic Verification of OTA Updates"]
    vul_ota_verification --> supply_chain_ota
    asset_ota_server["[A13] Tesla OTA Update Server (Purdue Level 3.5)"]
    asset_ota_server --> vul_ota_verification
    attacker --> asset_ota_server
    supply_chain_third_party["[H22] Trojanize Third-Party Apps in Tesla App Store"]
    supply_chain_third_party --> supply_chain_root
    vul_app_vetting["[V14] Insufficient Vetting of Third-Party Applications"]
    vul_app_vetting --> supply_chain_third_party
    asset_third_party_app_store["[A14] Tesla Third-Party App Repository"]
    asset_third_party_app_store --> vul_app_vetting
    attacker --> asset_third_party_app_store
    physical_access_root["[H23] Physical Access Exploits on IVI System"]
    physical_access_root --> root
    physical_usb_bad_usb["[H24] Execute BadUSB Attack via IVI USB Port"]
    physical_usb_bad_usb --> physical_access_root
    vul_usb_input_validation["[V15] Lack of Input Validation for USB HID Devices"]
    vul_usb_input_validation --> physical_usb_bad_usb
    asset_ivi_usb_port["[A15] USB Port in IVI Head Unit"]
    asset_ivi_usb_port --> vul_usb_input_validation
    attacker --> asset_ivi_usb_port
    physical_jtag_exploit["[H25] Exploit JTAG/UART Interfaces for Firmware Dumping"]
    physical_jtag_exploit --> physical_access_root
    vul_jtag_access_control["[V16] Unlocked JTAG/UART Debug Interfaces"]
    vul_jtag_access_control --> physical_jtag_exploit
    asset_ivi_debug_port["[A16] JTAG/UART Debug Port on IVI PCB"]
    asset_ivi_debug_port --> vul_jtag_access_control
    attacker --> asset_ivi_debug_port
    insider_threat_root["[H26] Insider Threat Exploits on IVI System"]
    insider_threat_root --> root
    insider_service_mode["[H27] Abuse Service Mode Diagnostic Commands"]
    insider_service_mode --> insider_threat_root
    vul_service_auth["[V17] Weak Authentication for Service Mode Access"]
    vul_service_auth --> insider_service_mode
    asset_service_diagnostic_tool["[A17] Tesla Service Diagnostic Tool/Software"]
    asset_service_diagnostic_tool --> vul_service_auth
    attacker --> asset_service_diagnostic_tool
    insider_backdoor["[H28] Activate Undocumented Backdoors in IVI Firmware"]
    insider_backdoor --> insider_threat_root
    vul_firmware_backdoor["[V18] Hardcoded Credentials/Backdoors in IVI Firmware"]
    vul_firmware_backdoor --> insider_backdoor
    asset_ivi_firmware_image["[A18] IVI Firmware Image (Encrypted Partition)"]
    asset_ivi_firmware_image --> vul_firmware_backdoor
    attacker --> asset_ivi_firmware_image