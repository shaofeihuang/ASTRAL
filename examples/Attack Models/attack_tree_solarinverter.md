graph BT
    root["[G01] Solar PV Cyber-Physical System (CPS) Disruption: Compromise inverter operations to disrupt grid stability, damage equipment, or halt power generation"]
    spoofing_root["[H01] Spoofing Attacks: Manipulate control signals or identities to deceive CPS components"]
    spoofing_root --> root
    spoofing_protocol["[H02] Protocol Spoofing: Exploit weak authentication in Modbus/DNP3/OPC UA to inject falsified commands"]
    spoofing_protocol --> spoofing_root
    modbus_no_auth["[V01] Modbus/DNP3 Lack of Authentication: Default configurations allow unauthenticated command injection"]
    modbus_no_auth --> spoofing_protocol
    modbus_inverter_cmd["[A01] Inverter Control Interface: Modbus/TCP port 502 exposed to spoofed setpoint injections (e.g., voltage/frequency adjustments)"]
    modbus_inverter_cmd --> modbus_no_auth
    attacker["[U01] Attacker"]
    attacker --> modbus_inverter_cmd
    dnp3_gateway["[A02] Gateway DNP3 Stack: Vulnerable to unauthenticated control messages from spoofed master stations"]
    dnp3_gateway --> modbus_no_auth
    attacker --> dnp3_gateway
    spoofing_firmware["[H03] Firmware Update Spoofing: Compromise update mechanisms to deploy malicious firmware"]
    spoofing_firmware --> spoofing_root
    unsecured_ota["[V02] Unsecured Over-the-Air (OTA) Updates: Lack of code-signing verification in inverter firmware update process"]
    unsecured_ota --> spoofing_firmware
    inverter_ota_port["[A03] Inverter OTA Update Port: HTTP/HTTPS endpoint (e.g., port 80/443) accepting unsigned firmware binaries"]
    inverter_ota_port --> unsecured_ota
    attacker --> inverter_ota_port
    cloud_update_server["[A04] Cloud Update Server: Compromised or spoofed server pushing backdoored firmware via MQTT/REST APIs"]
    cloud_update_server --> unsecured_ota
    attacker --> cloud_update_server
    spoofing_hmi["[H04] HMI Session Spoofing: Hijack operator sessions to issue unauthorized commands"]
    spoofing_hmi --> spoofing_root
    hmi_session_hijack["[V03] Weak Session Management: Predictable session tokens or missing CSRF protections in HMI web interface"]
    hmi_session_hijack --> spoofing_hmi
    hmi_web_portal["[A05] HMI Web Portal: Port 80/443 with cookie-based auth vulnerable to session replay"]
    hmi_web_portal --> hmi_session_hijack
    attacker --> hmi_web_portal
    tampering_root["[H05] Tampering Attacks: Unauthorized modification of hardware, software, or data"]
    tampering_root --> root
    tampering_physical["[H06] Physical Tampering: Direct manipulation of inverter hardware or local interfaces"]
    tampering_physical --> tampering_root
    unsecured_ports["[V04] Unsecured Local Ports: USB/serial/Ethernet ports with no authentication or logging"]
    unsecured_ports --> tampering_physical
    inverter_usb_port["[A06] Inverter USB Configuration Port: Exposed port allowing firmware flashes or debug access"]
    inverter_usb_port --> unsecured_ports
    attacker --> inverter_usb_port
    plc_serial_port["[A07] PLC Serial Port: RS-232/485 interface with default credentials for programming"]
    plc_serial_port --> unsecured_ports
    attacker --> plc_serial_port
    bypassed_safety["[V05] Safety Bypass Vulnerabilities: Jumpers or debug headers allowing disabling of protective relays"]
    bypassed_safety --> tampering_physical
    inverter_pcb["[A08] Inverter PCB: Exposed test points or jumpers to disable overvoltage/overcurrent protection"]
    inverter_pcb --> bypassed_safety
    attacker --> inverter_pcb
    tampering_comms["[H07] Communication Tampering: Intercept and modify in-transit data between components"]
    tampering_comms --> tampering_root
    unencrypted_fieldbus["[V06] Unencrypted Fieldbus Traffic: Modbus RTU/Profibus messages susceptible to MITM modifications"]
    unencrypted_fieldbus --> tampering_comms
    modbus_rtu_bus["[A09] Modbus RTU Bus: Shared serial bus between inverter and sensors/actuators (e.g., RS-485)"]
    modbus_rtu_bus --> unencrypted_fieldbus
    attacker --> modbus_rtu_bus
    rogue_gateway["[V07] Rogue Gateway Injection: Compromised protocol translator (e.g., Modbus-to-MQTT) altering telemetry/commands"]
    rogue_gateway --> tampering_comms
    protocol_gateway["[A10] Protocol Gateway Device: Linux/RTOS-based translator with weak access controls"]
    protocol_gateway --> rogue_gateway
    attacker --> protocol_gateway
    tampering_data["[H08] Data Integrity Tampering: Alter stored configurations or telemetry to induce unsafe operations"]
    tampering_data --> tampering_root
    unprotected_configs["[V08] Unprotected Configuration Files: Plaintext or weakly encrypted inverter settings (e.g., MPPT curves, grid codes)"]
    unprotected_configs --> tampering_data
    inverter_config_file["[A11] Inverter Configuration File: Stored on local flash or SD card with no integrity checks"]
    inverter_config_file --> unprotected_configs
    attacker --> inverter_config_file
    false_telemetry["[V09] False Telemetry Injection: Compromised sensors feeding manipulated data to control loops"]
    false_telemetry --> tampering_data
    temperature_sensor["[A12] Temperature Sensor: I2C/analog sensor feeding falsified overheating data to trigger shutdowns"]
    temperature_sensor --> false_telemetry
    attacker --> temperature_sensor
    repudiation_root["[H10] Repudiation Attacks: Obscure attack origins by exploiting weak logging or audit trails"]
    repudiation_root --> root
    missing_logs["[V10] Missing or Tamperable Logs: Inverter/PLC event logs disabled, overwritable, or stored in plaintext"]
    missing_logs --> repudiation_root
    inverter_event_log["[A13] Inverter Event Log: Local circular buffer with no cryptographic protections"]
    inverter_event_log --> missing_logs
    attacker --> inverter_event_log
    plc_audit_trail["[A14] PLC Audit Trail: Syslog/SEL events sent unencrypted to HMI, susceptible to interception/modification"]
    plc_audit_trail --> missing_logs
    attacker --> plc_audit_trail
    anonymous_actions["[V11] Anonymous Control Actions: Commands executed without operator attribution (e.g., Modbus function codes)"]
    anonymous_actions --> repudiation_root
    modbus_write_coils["[A15] Modbus Write Coils (FC5): Unattributed command to toggle inverter relays/breakers"]
    modbus_write_coils --> anonymous_actions
    attacker --> modbus_write_coils
    info_disclosure_root["[H12] Information Disclosure: Exfiltrate sensitive data to enable further attacks"]
    info_disclosure_root --> root
    unencrypted_comms["[V12] Unencrypted Communication Channels: Cleartext protocols leaking telemetry or credentials"]
    unencrypted_comms --> info_disclosure_root
    modbus_tcp_cleartext["[A16] Modbus/TCP Cleartext: Port 502 traffic exposing inverter registers (e.g., power output, faults)"]
    modbus_tcp_cleartext --> unencrypted_comms
    attacker --> modbus_tcp_cleartext
    mqtt_anonymous["[A17] Anonymous MQTT Broker: Telemetry published to unsecured MQTT topics (e.g., 'solar/inverter/#')"]
    mqtt_anonymous --> unencrypted_comms
    attacker --> mqtt_anonymous
    hardcoded_secrets["[V13] Hardcoded Credentials: Default or backdoor credentials in firmware/HMI"]
    hardcoded_secrets --> info_disclosure_root
    inverter_default_creds["[A18] Inverter Default Credentials: 'admin:admin' or vendor-specific backdoors in web interface"]
    inverter_default_creds --> hardcoded_secrets
    attacker --> inverter_default_creds
    plc_engineering_creds["[A19] PLC Engineering Credentials: Hardcoded 'service' account for vendor diagnostics"]
    plc_engineering_creds --> hardcoded_secrets
    attacker --> plc_engineering_creds
    firmware_reverse["[V14] Firmware Reverse Engineering: Extractable firmware binaries containing proprietary algorithms or crypto keys"]
    firmware_reverse --> info_disclosure_root
    inverter_firmware_bin["[A20] Inverter Firmware Binary: Downgradable or dumpable via JTAG/UART with weak readout protection"]
    inverter_firmware_bin --> firmware_reverse
    attacker --> inverter_firmware_bin
    dos_root["[H15] Denial-of-Service (DoS) Attacks: Disrupt inverter operations or communications"]
    dos_root --> root
    network_flooding["[V15] Network Flooding: Vulnerability to packet storms on fieldbus or IP networks"]
    network_flooding --> dos_root
    modbus_udp_flood["[A21] Modbus/UDP Flood: Port 502 UDP flood causing inverter communication timeout"]
    modbus_udp_flood --> network_flooding
    attacker --> modbus_udp_flood
    hmi_web_dos["[A22] HMI Web Interface: Slowloris-style attack on port 80/443 exhausting connections"]
    hmi_web_dos --> network_flooding
    attacker --> hmi_web_dos
    firmware_crash["[V16] Firmware Crash Triggers: Malformed packets or commands causing inverter reboot/lockup"]
    firmware_crash --> dos_root
    modbus_fuzz["[A23] Modbus Fuzzing: Crafted Modbus PDUs triggering buffer overflows in inverter stack"]
    modbus_fuzz --> firmware_crash
    attacker --> modbus_fuzz
    dnp3_malformed["[A24] Malformed DNP3 Objects: Invalid object headers causing PLC parse errors"]
    dnp3_malformed --> firmware_crash
    attacker --> dnp3_malformed
    physical_dos["[V17] Physical DoS: Overload or damage inverter components via control commands"]
    physical_dos --> dos_root
    overload_actuators["[A25] Actuator Overload: Rapid PWM cycling or relay toggling causing thermal stress"]
    overload_actuators --> physical_dos
    attacker --> overload_actuators
    grid_desync["[A26] Grid Desynchronization: Spoofed grid frequency commands forcing inverter trip"]
    grid_desync --> physical_dos
    attacker --> grid_desync
    eop_root["[H18] Elevation of Privilege: Gain unauthorized high-level access to inverter controls"]
    eop_root --> root
    privilege_escalation["[V18] Privilege Escalation: Exploit vulnerabilities to move from low to high privileges"]
    privilege_escalation --> eop_root
    hmi_rce["[V19] HMI Remote Code Execution: Buffer overflow in HMI web server (e.g., CVE-202X-1234)"]
    hmi_rce --> privilege_escalation
    hmi_web_server["[A27] HMI Web Server: Apache/Boa server with stack overflow in CGI handler"]
    hmi_web_server --> hmi_rce
    attacker --> hmi_web_server
    plc_ladder_logic["[V20] PLC Ladder Logic Injection: Unauthorized modifications to control logic via engineering port"]
    plc_ladder_logic --> privilege_escalation
    plc_programming_port["[A28] PLC Programming Port: Ethernet port with weak auth for ladder logic uploads"]
    plc_programming_port --> plc_ladder_logic
    attacker --> plc_programming_port
    credential_theft["[V21] Credential Theft: Extract or reuse credentials to access high-privilege functions"]
    credential_theft --> eop_root
    hmi_password_dump["[A29] HMI Password Database: Plaintext or weakly hashed credentials in HMI config files"]
    hmi_password_dump --> credential_theft
    attacker --> hmi_password_dump
    engineering_workstation["[A30] Engineering Workstation: Stored inverter/PLC credentials in vendor software (e.g., Siemens TIA Portal)"]
    engineering_workstation --> credential_theft
    attacker --> engineering_workstation
    lateral_root["[H22] Lateral Movement: Pivot from compromised components to target the inverter"]
    lateral_root --> root
    compromised_adjacent["[V22] Compromised Adjacent Systems: Exploit trust relationships with EMS/SCADA or peer inverters"]
    compromised_adjacent --> lateral_root
    ems_scada_link["[A31] EMS/SCADA Trusted Link: Modbus/OPC UA connection from compromised SCADA to inverter"]
    ems_scada_link --> compromised_adjacent
    attacker --> ems_scada_link
    peer_inverter["[A32] Peer Inverter: SunSpec/IEC 61850 trust relationship allowing lateral command injection"]
    peer_inverter --> compromised_adjacent
    attacker --> peer_inverter
    supply_chain_compromise["[V23] Supply Chain Compromise: Malicious components or updates from third-party vendors"]
    supply_chain_compromise --> lateral_root
    third_party_firmware["[A33] Third-Party Firmware: Compromised inverter firmware from OEM or integrator"]
    third_party_firmware --> supply_chain_compromise
    attacker --> third_party_firmware
    vendor_diagnostics["[A34] Vendor Diagnostic Tools: Backdoored engineering software (e.g., SolarEdge SetApp)"]
    vendor_diagnostics --> supply_chain_compromise
    attacker --> vendor_diagnostics