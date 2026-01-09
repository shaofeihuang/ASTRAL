graph BT
    root["[G01] Disruption or Stoppage of Cyber-Physical System Operations"]
    asset1["[A01] Patient Monitoring Devices"]
    asset1 --> root
    vul1["[V01] CVE-2021-3121 (Authentication Bypass)"]
    vul1 --> asset1
    haz1["[H01] Incorrect Dosage Delivery"]
    haz1 --> vul1
    attacker["[U01] Attacker"]
    attacker --> haz1
    asset2["[A02] Medical Data Storage Systems"]
    asset2 --> root
    vul2["[V02] CVE-2020-1472 (Zerologon)"]
    vul2 --> asset2
    haz2["[H02] Unauthorized Access to Sensitive Patient Data"]
    haz2 --> vul2
    attacker["[U01] Attacker"]
    attacker --> haz2
    asset3["[A03] Cloud-Based Analytics Platforms"]
    asset3 --> root
    vul3["[V03] DDoS Vulnerabilities"]
    vul3 --> asset3
    haz3["[H03] Disruption of Healthcare Services"]
    haz3 --> vul3
    attacker["[U01] Attacker"]
    attacker --> haz3
    asset4["[A04] Network Infrastructure"]
    asset4 --> root
    vul4["[V04] CVE-2020-0601 (Cryptographic Flaw)"]
    vul4 --> asset4
    haz4["[H04] Lateral Movement to OT Network"]
    haz4 --> vul4
    attacker["[U01] Attacker"]
    attacker --> haz4
    asset5["[A05] IoT Gateways"]
    asset5 --> root
    vul5["[V05] Default Credentials"]
    vul5 --> asset5
    haz5["[H05] Unauthorized Access to IoT Devices"]
    haz5 --> vul5
    attacker["[U01] Attacker"]
    attacker --> haz5
    asset6["[A06] SCADA System"]
    asset6 --> root
    vul6["[V06] Configuration Tampering"]
    vul6 --> asset6
    haz6["[H06] Unsafe Environmental Conditions"]
    haz6 --> vul6
    attacker["[U01] Attacker"]
    attacker --> haz6
    asset7["[A07] Medical Device Operating Systems"]
    asset7 --> root
    vul7["[V07] CVE-2021-34527 (Privilege Escalation)"]
    vul7 --> asset7
    haz7["[H07] Persistent Compromise of Hospital Network"]
    haz7 --> vul7
    attacker["[U01] Attacker"]
    attacker --> haz7