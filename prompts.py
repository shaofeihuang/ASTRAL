def create_arch_expl_prompt(system_context):
    prompt = f'''
You are a Senior Solution Architect tasked with explaining a system architectural diagram (e.g., Data Flow Diagram) to a Senior Security Architect experienced in IEC 62443 and the Purdue model. Your explanation supports threat modeling and attack tree development for a cyber-physical system, even if the architecture appears IT-centric.

System context: {system_context}

Thoroughly analyze the diagram and provide a structured explanation strictly based on visible content, covering:

1. Attacker or Attack-Capable Entities (explicit or implied, e.g., adversaries, operators)
2. Key Components (systems, devices, applications, network infrastructure, sensors, actuators, OT assets)
3. Trust Boundaries and Purdue Zones
4. Data Flows and Interactions (including protocols, data types, communication links)
5. Technologies, Platforms, and Standards
6. Assets and Functions with cyber-physical significance (PLCs, controllers, field devices, routers, meters, etc.)
7. Attack Entry Points (explicit or implied entities that could initiate attacks)
8. Any other architectural details supporting threat modeling and attack tree development

Structure your response using these exact section headers only:

- Attacker or Attack-Capable Entities  
- Key Components  
- Trust Boundaries and Purdue Zones  
- Data Flows & Interactions  
- Technologies and Protocols  
- Assets and Functions  
- Attack Entry Points  

IMPORTANT:
- Base your explanation solely on the provided diagram; do not infer or assume details beyond what is visible.
- Do not start or end with commentary or extra text.
- Do not infer or guess beyond what is visibly present.
- Do not provide recommendations—only factual explanation.
- Use only the specified headers and no additional formatting.
'''
    return prompt


def create_threat_model_prompt(system_context):
    prompt = f'''
You are a senior cyber security expert with over 20 years of experience in cyber-physical systems (CPS) risk and threat modeling, including deep expertise in STRIDE-LM and safety/security co-analysis. You have applied STRIDE-LM extensively in ICS, SCADA, and related CPS domains.

Your task is to analyze the provided system architectural diagram (e.g., Data Flow Diagram) along with any accompanying documentation to produce a comprehensive list of specific threat scenarios relevant to the application.

System context: {system_context}

Instructions:
1. If the diagram includes an "Attacker" entity—whether internal, external, explicit, or implicit—treat it as the origin for possible attack paths and enumerate realistic threats accordingly.
2. For each STRIDE-LM category, identify 3 to 4 credible threat scenarios if applicable. Each scenario must describe a concrete, context-specific attack, avoiding generic descriptions.
3. Focus your analysis on cyber-physical systems. Address system-level impacts such as disruption of physical processes, loss of control, cascading failures, or safety hazards rather than purely IT-centric threats.
4. Consider multiple potential attacker objectives (e.g., power disruption, asset damage, persistent foothold in isolated OT environments, bypassing safety controls).
5. Leverage and extract from the accompanying documentation to reflect the assets, vulnerabilities (both CVE-linked and non-CVE-linked), hazards, and objectives in each scenario.
6. Identify and list CVEs specific to the vulnerabilities visible in the accompanying documentation. For each CVE, provide the CVE identifier and a brief description. Indicate if the CVE has been observed in known attack campaigns (e.g., BlackEnergy, FrostyGoop), with references.
7. Apply FMECA-style reasoning where applicable to identify failure modes, their effects, and potential cascading consequences.
8. Format your response strictly as JSON with these top-level keys:
   - `"threat_model"`: an array of threat scenario objects.
   - `"improvement_suggestions"`: a list of missing information (e.g., authentication flows, protocol details, safety system integration, segmentation) needed for more precise modeling.
9. Each threat scenario object must contain the following keys:
   - `"Threat Type"`, based on STRIDE-LM categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege, Lateral Movement).
   - `"Scenario"`: a detailed narrative integrating information about assets, vulnerabilities (including CVE and non-CVE), hazards, and attacker objectives. Include references to any CVEs mentioned, and highlight if they were employed in known attack campaigns.
   - `"Potential Impact"`
10. Do NOT include general security recommendations or any commentary.
11. Provide no text outside the JSON structure.

This format ensures each threat scenario provides a clear, integrated explanation of the threat elements in a single narrative field, suitable for detailed CPS threat analysis.
'''
    return prompt


def create_attack_tree_prompt(system_context):
    prompt = """
Your task is to analyze the threat model and create an attack tree structure in JSON format.
The one and only root node represents the attack goal, which is the disruption or stoppage of cyber-physical system operations, taking into account the specific context of the system being analyzed.
Each node in the tree should represent an Asset, Vulnerability, Hazard, or Goal.
The tree should include all relevant attack paths and sub-paths based on the threat model.
Also analyse if assets, hazards, or vulnerabilities may be linked to assets, hazards, or vulnerabilities in separate attack paths, and if so, represent these relationships appropriately in the tree structure.
Each node label must begin with a prefix indicating its type:
- `[A##]` for Asset nodes
- `[V##]` for Vulnerability nodes
- `[H##]` for Hazard nodes
- `[G##]` for Goal node(s)

Relationships between nodes must obey these rules:
- Asset nodes may have children that are Vulnerabilities, Hazards, or other Assets.
- Goal node may have children that are Asset, Vulnerability or Hazard nodes.
- Vulnerability nodes may have children that are Vulnerabilities or Assets, but never Hazards.
- Hazard nodes may have children that are Hazards or Assets, but never Vulnerabilities.

Additionally, include a single attacker node at the bottom of the tree structure:
- The attacker node should be labeled with the prefix `[U01] Attacker`.
- This attacker node must have children links (edges) to all leaf nodes (the last nodes) in every attack path in the tree.
- This represents the attacker as the origin of all end-stage threats in the attack tree.

The JSON structure should follow this format:
{
    "nodes": [
        {
            "id": "root",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "auth",
                    "label": "Gain Unauthorized Access",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "Exploit OAuth2 Vulnerabilities",
                            "children": [
                                {
                                    "id": "attacker",
                                    "label": "[U01] Attacker"
                                }
                        }
                    ]
                }
            ]
        }
    ]
}

Rules:
- Use simple IDs (e.g., root, vul1, haz1, asset1).
- Make labels clear, descriptive, and correctly prefixed.
- Include all relevant attack paths and sub-paths.
- Maintain parent-child relationships strictly according to the rules above.
- Ensure the JSON is properly formatted.

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT.
"""
    return prompt


def create_aml_prompt_step_1(arch_explanation, threat_model, attack_paths):
    prompt = f"""
You are an expert AutomationML (IEC 62714) generator.

Given the following architectural explanation, threat model, and attack paths, generate AutomationML XML blocks defining all nodes as InternalElements with unique ExternalInterfaces.

- Do NOT generate any InternalLink elements in this step.
- Each node must have a unique ExternalInterface with a unique ID.
- Use exact node labels from inputs.
- Assign correct RefBaseSystemUnitPath based on node type:
  - Assets: AssetOfICS/SoftwareApplication for software applications, or AssetOfICS/Hardware/Machine for hardware components
  - Vulnerabilities: VulnerabilityforSystem/Vulnerability
  - Hazards: HazardforSystem/Hazard
  - Users/Attackers: AssetOfICS/User
- Node labels are prefixed by: `[A##]` for Assets, `[V##]` for Vulnerabilities, `[H##]` for Hazards,  `[U##]` for User or Attacker (the first node in the attack path), and `[G##]` for Goal (the last node in the attack path).
- Include basic attribute templates for each node type as below.

1. Asset:

<InternalElement Name="App" ID="[A01] App" RefBaseSystemUnitPath="AssetOfICS/Software/Application">
  <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
    <Attribute Name="Vendor" AttributeDataType="xs:string" />
    <Attribute Name="Part" AttributeDataType="xs:string" />
    <Attribute Name="Product" AttributeDataType="xs:string" />
    <Attribute Name="Version" AttributeDataType="xs:string" />
    <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float" />
    <Attribute Name="Impact Rating" AttributeDataType="xs:float" />
    <Attribute Name="Date of first use" AttributeDataType="xs:string" />
  </Attribute>          
  <ExternalInterface ...... />
</InternalElement>

2. User or Attacker:

<InternalElement Name="Attacker" ID="[U01] Attacker" RefBaseSystemUnitPath="AssetOfICS/User">
  <Attribute Name="HumanErrorEstimationPercentage" AttributeDataType="xs:string">
    <Value>100</Value>
  </Attribute>
  <ExternalInterface .... />
</InternalElement>

3. Vulnerabilities:

<InternalElement Name="...." ID="[V01] ...." RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
  <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
    <Attribute Name="CVE" AttributeDataType="xs:string" />
    <Attribute Name="CVSS" AttributeDataType="xs:string">
      <Value>....</Value>
    </Attribute>
    <Attribute Name="EPSS" AttributeDataType="xs:string" />
    <Attribute Name="Attack Name" AttributeDataType="xs:string" />
    <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
      <Value>....</Value>
    </Attribute>
    <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
      <Value>....</Value>
    </Attribute>
    <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
      <Value>....</Value>
    </Attribute>
  </Attribute>
  <ExternalInterface .... />
</InternalElement>

4. Hazards:

<InternalElement Name="...." ID="[H01] ...." RefBaseSystemUnitPath="HazardforSystem/Hazard">
  <Attribute Name="Impact Rating" AttributeDataType="xs:float" />
  <ExternalInterface .... />
</InternalElement>

Architecture Explanation:
{arch_explanation}

Threat Model:
{threat_model}

Attack Paths:
{attack_paths}

Output ONLY the InternalElement XML blocks with ExternalInterface elements, properly formatted.
"""
    return prompt


def create_aml_prompt_step_2(attack_paths):
    prompt = f"""
You are an expert at extracting directed edges from attack path sequences.

Given the following attack paths, output a JSON array listing all valid InternalLink pairs as [source_node_id, target_node_id], preserving direction exactly. Cover ALL attack paths.

Attack Paths:
{attack_paths}

Output ONLY the JSON array.
"""
    return prompt


def create_aml_prompt_step_3(valid_pairs_json, map_str):
    prompt = f"""
You are an AutomationML XML generator.

Using the following list of valid InternalLink pairs (source_node_id, target_node_id):

{valid_pairs_json}

And the following map of node IDs to ExternalInterface IDs:

{map_str}

Generate AutomationML InternalLink XML elements ONLY for these pairs.

Each InternalLink must have:

- RefPartnerSideA = Interface ID for the source node (source_node_id)
- RefPartnerSideB = Interface ID for the target node (target_node_id)
- Name attribute in the format: "{{source_node_id}}_{{target_node_id}}"

Do NOT generate any InternalLinks for pairs not in the list.

Output ONLY the InternalLink XML elements, properly formatted.
"""
    return prompt


def create_aml_prompt_step_4(internal_elements_xml, internal_links_xml):
    prompt = f"""
You are an AutomationML expert focused on generating a correct and IEC 62714-conformant AutomationML XML document.

Your task:
- Assemble a complete AutomationML XML document with InternalElements and their nested ExternalInterfaces and InternalLinks.
- Ensure full conformance with the IEC 62714 standard and AutomationML semantic modeling principles.
- All elements in {internal_elements_xml} must be included, including all Assets, Vulnerabilities, Hazards, Users/Attackers, and Goals. Do NOT generate any InternalElement not in the list.

Important structural and semantic requirements related to InternalElements:

1. **RefBaseSystemUnitPath Accuracy**:
  - Each InternalElement's RefBaseSystemUnitPath must exactly match the corresponding SystemUnitClass path in SystemUnitClassLib.
  - For example:
    - Software Applications: "AssetOfICS/Software/Application"
    - Hardware Machines: "AssetOfICS/Hardware/Machine"
    - Users/Attackers: "AssetOfICS/User"
    - Vulnerabilities: "VulnerabilityforSystem/Vulnerability"
    - Hazards: "HazardforSystem/Hazard"

2. **Attribute and Interface Correspondence**:
  - Attributes within InternalElements must align with those defined in the corresponding SystemUnitClass templates. Specifically:
    - Asset attributes are `Vendor`, `Version`, `FailureRatePerHour`, `Impact Rating`, and `Date of first use`.
    - Vulnerability attributes are `CVE`, `CVSS`, `EPSS`, `Attack Name`, `Probability of Impact`, `Probability of Exposure`, and `Probability of Mitigation`.
    - Hazard attributes are `Impact Rating`, `Consequence`, and `Causes`.
  - Include nested and typed Attributes as specified by the AttributeTypeLib.
  - ExternalInterface elements must use RefBaseClassPath referencing InterfaceClasses defined in InterfaceClassLib (e.g., "ConnectionBetnAssets/Network", "ConnectionBetnAssets/User").
  - Each InternalElement must have at least one ExternalInterface with a unique ID and appropriate Name.
  - Populate attribute values descriptively based on the provided input data.
  - *Do not assign CVEs that are not shown or mentioned in the provided input data.* Instead, assign assign CVE the value "N/A" and provide a synthetic CVSS vector reflecting the vulnerability description as the CVSS attribute.
  - Compute the Probability of Exposure attribute from the CVSS vector as Probability of Exposure = AV * AC * PR * UI, where AV, AC, PR, and UI come from the CVSS vector.
  - For vulnerabilities that are not linked to known CVEs based on the input information, assign the EPSS score (0 to 1) to both the EPSS attribute and Probability of Exposure attribute.
  - Do not assign EPSS scores to vulnerabilities that are not linked known CVEs.
  - Assign an estimate FailureRatePerHour (0 to 1) for assets if not shown or mentioned in the input information.
  - Assign an estimate Impact Rating (0 to 1) for assets and hazards based on the input information.

3. **InternalElement Naming and ID Conventions**:
  - Use standardized prefixes for element IDs and names to reflect their type:
    - Assets: `[A##]`
    - Vulnerabilities: `[V##]`
    - Hazards: `[H##]`
    - Users/Attackers: `[U##]`
    - Goals: `[G##]`
  - Ensure IDs are unique and consistent throughout the document.

4. **Hierarchical Consistency and Role Semantics**:
  - InternalElements should semantically inherit the structure and roles from their SystemUnitClass template.
  - Attributes and Interfaces absent in the SystemUnitClass template should not be arbitrarily added.
  - Follow the structural constraints enforced by the SystemUnitClassLib for nested elements and valid references.

Your output should be a syntactically valid, complete AutomationML XML file starting with:

<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="cps.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">

Include the SystemUnitClassLib, RoleClassLib, InterfaceClassLib, and AttributeTypeLib definitions exactly as provided.

Strictly output only the AutomationML XML file representing the system architecture, InternalElements, ExternalInterfaces, and InternalLinks per above rules. Do not include comments or anything else.

Output only if the following conditions are met:
1. All attributes in every InternalElement is populated.
2. CVSS is numeric.
3. EPSS, FailureRatePerHour, Impact Rating, Probability of Exposure, Probability of Impact, Probability of Mitigation are between 0 and 1.
4. Where CVEs are not applicable or not available from the input data, their values are 'N/A'.
5. Validate that all InternalLinks adhere to relationship rules and connect valid pairs only.


InternalElements XML 
{internal_elements_xml}

InternalLinks XML 
{internal_links_xml}

Use the following example AutomationML file as a reference for structure, conventions, and common patterns.

<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="CPS.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">
  
  <InstanceHierarchy Name="CPS Example">
    <Version>0</Version>

    <InternalElement Name="...." ID="[A01] ...." RefBaseSystemUnitPath="AssetOfICS/Software/Application">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>....</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>          
      <ExternalInterface Name="Interface_WebApp" ID="Interface_A01" RefBaseClassPath="ConnectionBetnAssets/Network" />
      <InternalLink RefPartnerSideA="Interface_A01" RefPartnerSideB="Interface_V01" Name="A01_V01" />
    </InternalElement>

    <InternalElement Name="Attacker" ID="[U01] Attacker" RefBaseSystemUnitPath="AssetOfICS/User">
      <Attribute Name="HumanErrorEstimationPercentage" AttributeDataType="xs:string">
        <Value>100</Value>
      </Attribute>
      <ExternalInterface Name="Interface_Attacker" ID="Interface_U01" RefBaseClassPath="ConnectionBetnAssets/User" />
      <InternalLink RefPartnerSideA="Interface_U01" RefPartnerSideB="Interface_A01" Name="U01_A01" />
    </InternalElement>
  </InstanceHierarchy>

  <InstanceHierarchy Name="Vulnerabilities">
    <Version>0</Version>
    <InternalElement Name="...." ID="...." RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string">
          <Value>..../Value>
        </Attribute>
        <Attribute Name="EPSS" AttributeDataType="xs:string" />
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>...</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>....</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="Interface_V01" ID="Interface_V01" RefBaseClassPath="ConnectionBetnAssets/Network" />
      <InternalLink RefPartnerSideA="Interface_V01" RefPartnerSideB="Interface_V02" Name="V01_V02" />
    </InternalElement>
  </InstanceHierarchy>

  <InstanceHierarchy Name="Hazards" ID="a8f06f3b-9aa4-4e84-96d9-fc8f22cf4109">
    <Version>1.0.0</Version>
    <InternalElement Name="...." ID="...." RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <Attribute Name="Impact Rating" AttributeDataType="xs:float" />
      <ExternalInterface Name="Interface_H01" ID="Interface_H01" RefBaseClassPath="ConnectionBetnAssets/User" />
      <InternalLink RefPartnerSideA="Interface_H01" RefPartnerSideB="Interface_H2" Name="H01_H02" />
    </InternalElement>
  </InstanceHierarchy>

  <InterfaceClassLib Name="ConnectionBetnAssets">
    <Version>0</Version>
    <InterfaceClass Name="Network" />
    <InterfaceClass Name="Logic" />
    <InterfaceClass Name="User" />
  </InterfaceClassLib>

  <RoleClassLib Name="Requirements">
    <Version>0</Version>
    <RoleClass Name="Process" />
    <RoleClass Name="Safety" />
    <RoleClass Name="Security" />
    <RoleClass Name="Communication" />
  </RoleClassLib>

  <SystemUnitClassLib Name="AssetOfICS">
    <Version>0</Version>
    <SystemUnitClass Name="Hardware" ID="">
      <SystemUnitClass Name="Process device" ID="218aad50-66b5-4205-bedb-82909071132c">
        <SystemUnitClass Name="Sensor" ID="49f8334e-4394-49c7-adb6-d6cbebe9891c">
          <ExternalInterface Name="SensorOP" ID="2ef137de-c2f2-4a3b-9e3a-eecf3ef300cd" RefBaseClassPath="ConnectionBetnAssets/Network based" />
          <ExternalInterface Name="SensorOP" ID="c499308a-34d9-4fab-9c61-11387c1cc90a" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Actuator" ID="6c85b309-07b2-45c5-93ef-13cc3346c193">
          <ExternalInterface Name="ActuatorIP" ID="59442097-a731-4196-a92c-f1395a3580df" RefBaseClassPath="ConnectionBetnAssets/Network based" />
          <ExternalInterface Name="ActuatorIP" ID="51d73d1b-7def-4558-b7fb-a4d01a0d66fb" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Controller" ID="69411186-9377-4863-b9a0-73aad465cf26">
          <ExternalInterface Name="IOfromController" ID="8c32edd2-9e17-4f2c-af8f-0b522ba3cbba" RefBaseClassPath="ConnectionBetnAssets/Network based" />
          <ExternalInterface Name="IOfromController" ID="f7cca4aa-5443-424b-86f4-0c8c8deaa225" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Workstation" ID="17945b57-6f0d-4017-881e-41a126e3f90e">
          <ExternalInterface Name="IOfromWS" ID="52d38b0f-d3f7-4bdb-abc0-16e9dabea340" RefBaseClassPath="ConnectionBetnAssets/Network based" />
          <ExternalInterface Name="IOfromWS" ID="fa8ebac1-c41b-465d-8fc2-a6582d09e1f7" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Server" ID="bec0cd86-fc7f-4162-bcea-05ed9d32fc04">
          <ExternalInterface Name="IOfromServer" ID="09a7a80b-0508-4024-9b7a-5cfffb311cff" RefBaseClassPath="ConnectionBetnAssets/Network based" />
          <ExternalInterface Name="IOfromServer" ID="1479458e-8116-4c70-adc7-0c791e0e1473" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
        </SystemUnitClass>
      </SystemUnitClass>
      <SystemUnitClass Name="Machine" ID="b0b90afc-e54a-4f70-ad1a-b57a6aa37126">
        <ExternalInterface Name="IOfromMC" ID="fc6f76bc-152e-43d9-bf23-4e913d46feac" RefBaseClassPath="ConnectionBetnAssets/Network based" />
        <ExternalInterface Name="IOfromMC" ID="e7ed45fb-c6e1-46d2-93a6-53d23457768c" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
      </SystemUnitClass>
      <SystemUnitClass Name="Network Devices" ID="57b6aead-570b-4a12-b8d9-f946373e97a7">
        <SystemUnitClass Name="IO module" ID="c69ab963-3222-422b-95e7-4e6bb2989149">
          <ExternalInterface Name="IOfromModule" ID="e0769d3b-4e2a-43fd-b393-fc62a42de931" RefBaseClassPath="ConnectionBetnAssets/Network based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Switch" ID="cf31e0ad-1585-44a0-9685-0626236f3604">
          <ExternalInterface Name="IOfromSwitch" ID="fd0f57a1-533b-4461-b153-92ec483a1dcb" RefBaseClassPath="ConnectionBetnAssets/Network based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Router" ID="b84bf1ba-d7b9-457d-a93d-75f384d8e708">
          <ExternalInterface Name="IOfromRouter" ID="905312d1-bb97-4817-ad2d-66ec3b47851b" RefBaseClassPath="ConnectionBetnAssets/Network based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Gateway" ID="bc4bd051-6e3d-4db3-a94c-01e616da50ef">
          <ExternalInterface Name="IOfromGateway" ID="783db18b-fbf8-4caf-ab8d-0fd346a392bf" RefBaseClassPath="ConnectionBetnAssets/Network based" />
        </SystemUnitClass>
        <SystemUnitClass Name="Firewall" ID="592c3197-2afb-42dc-950a-c3018f39a88c">
          <ExternalInterface Name="IOfromFirewall" ID="9693d158-e354-49fa-bc8c-aba24c759d4a" RefBaseClassPath="ConnectionBetnAssets/Network based" />
        </SystemUnitClass>
      </SystemUnitClass>
      <SystemUnitClass Name="Non-Automation Devices" ID="6ae4f50f-cc50-4e0d-bd12-c5a4ac456808" />
    </SystemUnitClass>
    <SystemUnitClass Name="Software" ID="55ba674e-2081-4940-8452-44395105cbb3">
      <SystemUnitClass Name="Firmware/ Operating system" ID="4f9da684-0682-4997-8895-e798b5378d8c" />
      <SystemUnitClass Name="Application" ID="3932b7d5-9b84-4c3f-a14a-e8f025342011" />
      <SystemUnitClass Name="Process logic" ID="df9f1505-ebbd-4e0c-9aba-bcc917518086" />
      <SystemUnitClass Name="OT adapters" ID="01227b68-027c-4b0c-a656-182d97d4f41d" />
    </SystemUnitClass>
    <SystemUnitClass Name="User" ID="b1a381bb-985e-4b50-93d3-98b02d304ccd">
      <ExternalInterface Name="IOfromUser" ID="72bfd734-8588-4801-9e7a-ed486ca78dd7" RefBaseClassPath="ConnectionBetnAssets/User based" />
    </SystemUnitClass>
  </SystemUnitClassLib>

  <SystemUnitClassLib Name="HazardforSystem">
    <Version>0</Version>
    <SystemUnitClass Name="Hazard" ID="e5aa0b0e-32ee-4bb3-a28b-b08ac4cdc5f5">
      <ExternalInterface Name="HazardRef" ID="e76420a9-0048-4aca-91b3-b7109a6e531b" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
    </SystemUnitClass>
  </SystemUnitClassLib>

  <SystemUnitClassLib Name="VulnerabilityforSystem">
    <Version>0</Version>
    <SystemUnitClass Name="Vulnerability" ID="61c989ba-67ff-4aa8-9daa-937a4d45e0a3">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="b623ff6d-1c1a-4f45-b260-965e18c18863" />
      <Attribute Name="EPSS" AttributeDataType="xs:string" ID="b623ff6d-1c1a-4f45-b260-965e18c18863" />
      <Attribute Name="Attack Name" AttributeDataType="xs:string" />
      <ExternalInterface Name="VulnerabilityRef" ID="32ebc8a3-9568-4deb-a92e-e8647789d8a3" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
    </SystemUnitClass>
  </SystemUnitClassLib>

  <AttributeTypeLib Name="AttributeTypeLib">
    <Version>0</Version>
    <AttributeType Name="AutomationEquipments" AttributeDataType="xs:string">
      <Attribute Name="Vendor" AttributeDataType="xs:string" />
      <Attribute Name="Part" AttributeDataType="xs:string" />
      <Attribute Name="Product" AttributeDataType="xs:string" />
      <Attribute Name="Version" AttributeDataType="xs:string" />
      <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float" />
      <Attribute Name="Date of first use" AttributeDataType="xs:string" />
    </AttributeType>
    <AttributeType Name="Hazard" AttributeDataType="xs:string">
      <Attribute Name="Name" AttributeDataType="xs:string" />
      <Attribute Name="Severity" AttributeDataType="xs:string" />
      <Attribute Name="Probability" AttributeDataType="xs:string" />
      <Attribute Name="Consequence" AttributeDataType="xs:string" />
      <Attribute Name="Causes" AttributeDataType="xs:string" />
    </AttributeType>
    <AttributeType Name="Vulnerability" AttributeDataType="xs:string">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:T/RC:R" />
      <Attribute Name="EPSS" AttributeDataType="xs:string" />
      <Attribute Name="Attack Name" AttributeDataType="xs:string" />
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string" />
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string" />
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string" />
    </AttributeType>
  </AttributeTypeLib>
</CAEXFile>
"""
    return prompt

#  - InternalLinks must be nested inside the InternalElements referencing the ExternalInterface ID of RefPartnerSideA.




def create_dread_assessment_prompt(threats, system_context):
    prompt = f"""
You are a cyber security expert with more than 20 years of experience in threat modeling using STRIDE-LM and DREAD methodologies.
Your task is to produce a DREAD risk assessment for the threats identified in a threat model, relevant to the following system context: {system_context}.
Below is the list of identified threats:
{threats}
When providing the risk assessment, use a JSON formatted response with a top-level key "Risk Assessment" and a list of threats, each with the following sub-keys:
- "Threat Type": A string representing the type of threat (e.g., "Spoofing").
- "Scenario": A string describing the threat scenario.
- "Damage Potential": An integer between 1 and 10.
- "Reproducibility": An integer between 1 and 10.
- "Exploitability": An integer between 1 and 10.
- "Affected Users": An integer between 1 and 10.
- "Discoverability": An integer between 1 and 10.
Assign a value between 1 and 10 for each sub-key based on the DREAD methodology. Use the following scale:
- 1-3: Low
- 4-6: Medium
- 7-10: High
Ensure the JSON response is correctly formatted and does not contain any additional text. Here is an example of the expected JSON response format:
{{
  "Risk Assessment": [
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could create a fake OAuth2 provider and trick users into logging in through it.",
      "Damage Potential": 8,
      "Reproducibility": 6,
      "Exploitability": 5,
      "Affected Users": 9,
      "Discoverability": 7
    }},
    {{
      "Threat Type": "Spoofing",
      "Scenario": "An attacker could intercept the OAuth2 token exchange process through a Man-in-the-Middle (MitM) attack.",
      "Damage Potential": 8,
      "Reproducibility": 7,
      "Exploitability": 6,
      "Affected Users": 8,
      "Discoverability": 6
    }}
  ]
}}
"""
    return prompt

