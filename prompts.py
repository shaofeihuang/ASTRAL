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


def create_aml_prompt_v1(arch_explanation, threat_model, attack_tree):
    prompt = f"""
You are an expert in AutomationML (AML) file generation according to the IEC 62714 standard.

Your task is to generate an AutomationML representation of the cyber-physical system architecture with integrated security modelling elements based on the provided architectural explanation, threat model, and attack tree.

Strictly follow these instructions:

1. Represent Core Elements:
   - Model Assets as `InternalElement` objects with attributes including `Vendor`, `Version`, `FailureRatePerHour`, `Impact Rating`, and `Date of first use`.
   - Model Vulnerabilities as `InternalElement` objects with attributes `CVE`, `CVSS`, `Attack Name`, `Probability of Impact`, `Probability of Exposure`, `Probability of Mitigation`, and `EPSS`.
   - Model Hazards as `InternalElement` objects with attributes such as `Impact Rating`, `Consequence`, and `Causes`.
   - Model Relationships as `InternalLink` objects connecting assets, vulnerabilities, and hazards.

2. Follow Relationship Rules:
   - Assets may link to Assets, Vulnerabilities, or Hazards.
   - Hazards may link to Assets or Hazards.
   - Vulnerabilities may link to Assets or Vulnerabilities.
   - Assets, Vulnerabilities, and Hazards may link to Goal nodes (modeled as Hazards), which are leaf nodes without children.

3. Represent the System Architecture:
   - Use node labels prefixed by `[A##]` for Assets, `[V##]` for Vulnerabilities, `[H##]` for Hazards, and `[G##]` for the ultimate Goal hazards.
   - Integrate relationships from the architecture diagram and attack tree into the AutomationML model using `ExternalInterface` and `InternalLink` constructs.
   - Ensure parent-child hierarchical relationships conform to the relationship rules above.

4. Class Paths and Interfaces:
   - Use appropriate class paths such as `AssetOfICS/SoftwareApplication` for assets, `VulnerabilityforSystem/Vulnerability` for vulnerabilities, `HazardforSystem/Hazard` for hazards.
   - Define interfaces using the `ConnectionBetnAssets` interface classes (`Network based`, `Logic based`, `User based`, `HazardRef`, `VulnerabilityRef`).

Use the following example AutomationML file as a reference for structure, conventions, and common patterns.

<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="CPS.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">
  <InstanceHierarchy Name="CPS">
    <Version>0</Version>
    <InternalElement Name="ICS Workstation" ID="[A01] ICS_Workstation" RefBaseSystemUnitPath="AssetOfICS/Hardware/Process device/Workstation">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>1.48254E-05</Value>
        </Attribute>
        <Attribute Name="Impact Rating" AttributeDataType="xs:float">
          <Value>0.363636364</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>
      <ExternalInterface Name="toHazard" ID="629f5ad5-bf5f-43c1-b20f-89ae3b71c3f8" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <ExternalInterface Name="toVulnerability" ID="6e05a84b-54d8-4d39-a98d-819ac4c0a435" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Security" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Process" />
    </InternalElement>

    <InternalElement Name="Attacker" ID="[U01] Attacker" RefBaseSystemUnitPath="AssetOfICS/User">
      <Attribute Name="HumanErrorEstimationPercentage" AttributeDataType="xs:string">
        <Value>5</Value>
      </Attribute>
      <ExternalInterface Name="toHazard" ID="870bb67c-df05-42e3-9bb8-1783bdb2e5e6" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <ExternalInterface Name="toVulnerability" ID="74070941-2c10-46c7-a846-1cc17ccec0cc" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Process" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Safety" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Security" />
    </InternalElement>
  </InstanceHierarchy>

  <InstanceHierarchy Name="Hazards">
    <Version>0</Version>
    <InternalElement Name="[H01] Fall prey to spear-phishing attack" ID="H1_Spearphishing" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <Attribute Name="Name" AttributeDataType="xs:string" />
      <Attribute Name="Probability" AttributeDataType="xs:string" />
      <Attribute Name="Impact Rating" AttributeDataType="xs:float">
        <Value>0.25</Value>
      </Attribute>
      <ExternalInterface Name="ToHaz01" ID="26dc9b7a-8ef2-40c3-bd8d-1de83035f170" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="26dc9b7a-8ef2-40c3-bd8d-1de83035f170" RefPartnerSideB="47e39df6-9af5-4522-b445-9e17a83f2d83" Name="InternalLink" />
    </InternalElement>

  <InstanceHierarchy Name="Vulnerabilities">
    <Version>0</Version>
    <InternalElement Name="[V01] Microsoft Word 0-Day Vulnerability" ID="V1" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string">
        <Value>CVE-2014-4114</Value>
      </Attribute>
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="34643025-7ad6-4dc0-a9aa-833394f9f835">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="EPSS" AttributeDataType="xs:string">
        <Value>0.92</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>Sandworm</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.9219</Value>
      </Attribute>
      <ExternalInterface Name="ToV1" ID="47e39df6-9af5-4522-b445-9e17a83f2d83" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="47e39df6-9af5-4522-b445-9e17a83f2d83" RefPartnerSideB="de6258a7-8d39-4711-8414-f866f4999249" Name="InternalLink" />
    </InternalElement>

  </InstanceHierarchy>
  <InterfaceClassLib Name="ConnectionBetnAssets">
    <Version>0</Version>
    <InterfaceClass Name="Network based" />
    <InterfaceClass Name="Logic based" />
    <InterfaceClass Name="User based" />
    <InterfaceClass Name="HazardRef" />
    <InterfaceClass Name="VulnerabilityRef" />
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
      <Attribute Name="CVSS" AttributeDataType="xs:string" />
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
      <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
      </Attribute>
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
      <Attribute Name="CVSS" AttributeDataType="xs:string" />
      <Attribute Name="EPSS" AttributeDataType="xs:string" />
      <Attribute Name="Attack Name" AttributeDataType="xs:string" />
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string" />
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string" />
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string" />
    </AttributeType>
  </AttributeTypeLib>
</CAEXFile>

Inputs:

Architecture Explanation:
{arch_explanation}

Threat Model:
{threat_model}

Attack Tree:
{attack_tree}

Output Requirements:

Pay careful attention to the following:
- Produce syntactically valid AutomationML XML representing the system architecture and security model elements.
- Populate attribute values descriptively based on the provided input data.
- For vulnerabilities without known CVEs, assign CVE the value "N/A" and provide a synthetic CVSS vector reflecting the vulnerability description as the CVSS attribute.
- Compute the Probability of Exposure attribute based on the CVSS vector using the formula: Probability of Exposure = AV * AC * PR * UI, where AV, AC, PR, and UI are derived from the CVSS vector.
- For vulnerabilities with known CVEs, retrieve and assign the EPSS score (ranging from 0 to 1) to both the EPSS attribute and Probability of Exposure attribute.
- Do not assign EPSS scores to vulnerabilities without known CVEs.
- Estimate FailureRatePerHour (between 0 and 1) for assets when not explicitly provided, using typical values for comparable components.
- Estimate Impact Rating (between 0 and 1) for assets and hazards based on analysis of the threat model and attack tree; higher values indicate greater criticality.
- Include all required InternalElement and InternalLink elements to accurately reflect asset, vulnerability, hazard, attacker, and goal relationships, and attack paths derived from the threat model and attack tree.
- The Attacker must be linked to an Asset, Vulnerability, or Hazard.
- The Goal must be linked to an Asset, Vulnerability, or Hazard.
- Ensure that ExternalInterface ID tags are unique across different elements.
- Ensure that ExternalInterface ID tags are correctly mirrored in the RefPartnerSideA or RefPartnerSideB tags in the InternalLinks of connections between elements.

- The output must be a valid AutomationML XML file content, starting with the XML declaration:
<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="cps.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">
  <InstanceHierarchy Name="CPS">
    <Version>0</Version>

- Maintain proper XML indentation and well-formed structure.
- Include all relevant components and threat considerations as per the inputs.
- Do NOT include any explanations or extra text, only the AutomationML XML content.

Generate the AutomationML file now.
"""
    return prompt



def create_aml_prompt(arch_explanation, threat_model, attack_tree):
    prompt = f"""
You are an expert in AutomationML (AML) file generation according to the IEC 62714 standard.

Your task is to generate an AutomationML representation of the cyber-physical system architecture with integrated security modelling elements based on the provided architectural explanation, threat model, and attack tree.

Strictly follow these instructions:

1. Represent Core Elements:
   - Model Assets as `InternalElement` objects with attributes including `Vendor`, `Version`, `FailureRatePerHour`, `Impact Rating`, and `Date of first use`.
   - Model Vulnerabilities as `InternalElement` objects with attributes `CVE`, `CVSS`, `Attack Name`, `Probability of Impact`, `Probability of Exposure`, `Probability of Mitigation`, and `EPSS`.
   - Model Hazards as `InternalElement` objects with attributes such as `Impact Rating`, `Consequence`, and `Causes`.
   - Model Relationships as `InternalLink` objects connecting assets, vulnerabilities, and hazards.

2. Follow Relationship Rules:
   - Assets may link to Assets, Vulnerabilities, or Hazards.
   - Hazards may link to Assets or Hazards.
   - Vulnerabilities may link to Assets or Vulnerabilities.
   - Assets, Vulnerabilities, and Hazards may link to Goal nodes (modeled as Hazards), which are leaf nodes without children.

3. Represent the System Architecture:
   - Use node labels prefixed by `[A##]` for Assets, `[V##]` for Vulnerabilities, `[H##]` for Hazards, and `[G##]` for the ultimate Goal hazards.
   - Integrate relationships from the architecture diagram and attack tree into the AutomationML model using `ExternalInterface` and `InternalLink` constructs.
   - Ensure parent-child hierarchical relationships conform to the relationship rules above.

4. Class Paths and Interfaces:
   - Use appropriate class paths such as `AssetOfICS/SoftwareApplication` for assets, `VulnerabilityforSystem/Vulnerability` for vulnerabilities, `HazardforSystem/Hazard` for hazards.
   - Define interfaces using the `ConnectionBetnAssets` interface classes (`Network based`, `Logic based`, `User based`, `HazardRef`, `VulnerabilityRef`).

5. Important: Unique IDs for ExternalInterfaces and InternalLinks
   - Each `ExternalInterface` element must have a globally unique `ID` attribute. Do NOT reuse or copy any `ID` values across different `ExternalInterface` elements, even if their `Name` or `RefBaseClassPath` is identical.
   - Generate or assign a unique UUID (Universally Unique Identifier) string for every `ExternalInterface` ID.
   - For every connection between elements, mirror the `ExternalInterface` IDs correctly in the corresponding `InternalLink`'s `RefPartnerSideA` and `RefPartnerSideB` attributes.
   - Failure to maintain unique `ExternalInterface` IDs will cause invalid XML and break AutomationML conformance.

Use the following example AutomationML file as a reference for structure, conventions, and common patterns.


<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="x.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">
  
  <InstanceHierarchy Name="Solar PV Example">
    <Version>0</Version>

    <InternalElement Name="Mobile/Web App" ID="Mobile_Web_App" RefBaseSystemUnitPath="AssetOfICS/Software/Application">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>0.01</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>          
      <ExternalInterface Name="IO" ID="b6fecd68-6843-4fe6-825e-79a9c71cfee9" RefBaseClassPath="ConnectionBetnAssets/User based" />
      <ExternalInterface Name="ToVulnerability" ID="1471031b-c125-4174-9b1c-a6e26de47aa8" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="1471031b-c125-4174-9b1c-a6e26de47aa8" RefPartnerSideB="911514f8-0f3b-4196-85f0-95efbd8fce81" Name="VLink" />
      <InternalLink RefPartnerSideA="1471031b-c125-4174-9b1c-a6e26de47aa8" RefPartnerSideB="07c071d3-c63b-422e-9e6d-122713068187" Name="VLink1" />
      <InternalLink RefPartnerSideA="1471031b-c125-4174-9b1c-a6e26de47aa8" RefPartnerSideB="9127963f-a666-4252-baa5-a8287b4ce75c" Name="VLink2" />
      <ExternalInterface Name="ToHazard" ID="b4968b6f-235d-46c8-9d05-f8b80df61eea" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="b4968b6f-235d-46c8-9d05-f8b80df61eea" RefPartnerSideB="5cea00b2-17c7-4c88-a6a5-68dbce257bf5" Name="HLink" />
      <InternalLink RefPartnerSideA="b4968b6f-235d-46c8-9d05-f8b80df61eea" RefPartnerSideB="2cfaa84f-2283-4ba1-b854-67062f08337f" Name="HLink1" />
      <InternalLink RefPartnerSideA="b4968b6f-235d-46c8-9d05-f8b80df61eea" RefPartnerSideB="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" Name="HLink2" />
    </InternalElement>

    <InternalElement Name="WiNet Web" ID="WiNet_Web" RefBaseSystemUnitPath="AssetOfICS/Software/Application">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>0.01</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>
      <ExternalInterface Name="IO" ID="9901a662-edd9-4eac-8f00-97be82bb83cf" RefBaseClassPath="ConnectionBetnAssets/User based" />
      <ExternalInterface Name="ToVulnerability" ID="9c223d01-24b4-4dc5-b5fb-766f6d45c1ab" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="9c223d01-24b4-4dc5-b5fb-766f6d45c1ab" RefPartnerSideB="fc2b3b23-5dec-4004-8f2e-14f7b12355ec" Name="VLink" />
      <ExternalInterface Name="ToHazard" ID="967f4b19-bc60-495a-9833-eb1c9fa2fba5" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="967f4b19-bc60-495a-9833-eb1c9fa2fba5" RefPartnerSideB="5cea00b2-17c7-4c88-a6a5-68dbce257bf5" Name="HLink" />
    </InternalElement>

    <InternalElement Name="iSolarCloud MQTT Broker" ID="MQTT_Broker" RefBaseSystemUnitPath="AssetOfICS/Software/Application">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>0.01</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" /> 
      </Attribute>
      <ExternalInterface Name="ToVulnerability" ID="bbba14d7-f291-4974-b4c0-53a29bd7f33d" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="bbba14d7-f291-4974-b4c0-53a29bd7f33d" RefPartnerSideB="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" Name="VLink" />
      <InternalLink RefPartnerSideA="bbba14d7-f291-4974-b4c0-53a29bd7f33d" RefPartnerSideB="cc102c11-c2f8-4b95-9701-2c975f5ea63b" Name="VLink1" />
      <InternalLink RefPartnerSideA="bbba14d7-f291-4974-b4c0-53a29bd7f33d" RefPartnerSideB="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" Name="VLink2" />
      <InternalLink RefPartnerSideA="bbba14d7-f291-4974-b4c0-53a29bd7f33d" RefPartnerSideB="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" Name="VLink3" />
      <InternalLink RefPartnerSideA="bbba14d7-f291-4974-b4c0-53a29bd7f33d" RefPartnerSideB="adfd6ccf-c3c7-4929-b69c-1d5232b48617" Name="VLink4" />
      <ExternalInterface Name="ToHazard" ID="2ea0d12b-5f6f-4111-8f24-f9a2aa7e3b32" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="2ea0d12b-5f6f-4111-8f24-f9a2aa7e3b32" RefPartnerSideB="5cea00b2-17c7-4c88-a6a5-68dbce257bf5" Name="HLink" />
      <InternalLink RefPartnerSideA="2ea0d12b-5f6f-4111-8f24-f9a2aa7e3b32" RefPartnerSideB="2cfaa84f-2283-4ba1-b854-67062f08337f" Name="HLink1" />
      <InternalLink RefPartnerSideA="2ea0d12b-5f6f-4111-8f24-f9a2aa7e3b32" RefPartnerSideB="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" Name="HLink2" />
    </InternalElement>

    <InternalElement Name="WiNet-S Comms Dongle" ID="Comms_Dongle" RefBaseSystemUnitPath="AssetOfICS/Hardware/Machine">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>0.0000148254</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>
      <ExternalInterface Name="ToVulnerability" ID="b64a1153-5840-4a28-9027-ee37f10c305c" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef">
        <ExternalInterface Name="ToV15" ID="de62cb76-82fd-4202-8ea5-099b830a819c" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      </ExternalInterface>
      <ExternalInterface Name="IO" ID="4e6d78bb-e979-4313-9af1-f24d51aaa59f" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
      <InternalLink RefPartnerSideA="4e6d78bb-e979-4313-9af1-f24d51aaa59f" RefPartnerSideB="86c10f25-197c-4be8-a622-8dd1870a276c" Name="LLink" />
      <ExternalInterface Name="ToHazard" ID="d1801042-79e9-4051-883f-ad20f98ab96f" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="4e6d78bb-e979-4313-9af1-f24d51aaa59f" RefPartnerSideB="86c10f25-197c-4be8-a622-8dd1870a276c" Name="HLink" />
      <InternalLink RefPartnerSideA="d1801042-79e9-4051-883f-ad20f98ab96f" RefPartnerSideB="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" Name="HLink1" />
    </InternalElement>

    <InternalElement Name="Solar PV Inverter" ID="Solar_PV_Inverter" RefBaseSystemUnitPath="AssetOfICS/Hardware/Machine">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>0.0000148254</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>
      <ExternalInterface Name="ToVulnerability" ID="de0c78d2-a59d-4936-ad15-b880b4ceae4f" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <ExternalInterface Name="IO" ID="86c10f25-197c-4be8-a622-8dd1870a276c" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
      <InternalLink RefPartnerSideA="86c10f25-197c-4be8-a622-8dd1870a276c" RefPartnerSideB="819b9d06-b4f6-4ca0-b94c-3a98b0b1ff6b" Name="LLink" />
      <InternalLink RefPartnerSideA="de0c78d2-a59d-4936-ad15-b880b4ceae4f" RefPartnerSideB="099916f1-a2df-4241-a6b1-5912fe33cb85" Name="LLink1" />
      <InternalLink RefPartnerSideA="6d2d016c-d1f8-4093-93b5-1e5703d8d486" RefPartnerSideB="4ee29329-32de-46a6-ba7f-c80207d2767a" Name="LLink2" />
      <ExternalInterface Name="ToHazard" ID="6d2d016c-d1f8-4093-93b5-1e5703d8d486" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="86c10f25-197c-4be8-a622-8dd1870a276c" RefPartnerSideB="819b9d06-b4f6-4ca0-b94c-3a98b0b1ff6b" Name="HLink" />
      <InternalLink RefPartnerSideA="6d2d016c-d1f8-4093-93b5-1e5703d8d486" RefPartnerSideB="2cd7055d-a75d-4a97-bee6-65ebae7cecda" Name="HLink1" />
      <InternalLink RefPartnerSideA="6d2d016c-d1f8-4093-93b5-1e5703d8d486" RefPartnerSideB="4ee29329-32de-46a6-ba7f-c80207d2767a" Name="HLink2" />
    </InternalElement>

    <InternalElement Name="Power Grid" ID="Power_Grid" RefBaseSystemUnitPath="AssetOfICS/Hardware/Machine">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>0.0000148254</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>
      <ExternalInterface Name="ToVulnerability" ID="cb07ea86-fba4-43e0-8b9b-7fbf852b4d5c" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <ExternalInterface Name="IO" ID="819b9d06-b4f6-4ca0-b94c-3a98b0b1ff6b" RefBaseClassPath="ConnectionBetnAssets/Logic based" />
      <InternalLink RefPartnerSideA="1d008df3-1533-491a-bfb0-e05f61a16c53" RefPartnerSideB="4ee29329-32de-46a6-ba7f-c80207d2767a" Name="LLink" />
      <InternalLink RefPartnerSideA="1d008df3-1533-491a-bfb0-e05f61a16c53" RefPartnerSideB="8b0902ce-e7ab-421e-ab75-770df99554cd" Name="LLink1" />
      <ExternalInterface Name="ToHazard" ID="1d008df3-1533-491a-bfb0-e05f61a16c53" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="1d008df3-1533-491a-bfb0-e05f61a16c53" RefPartnerSideB="4ee29329-32de-46a6-ba7f-c80207d2767a" Name="HLink" />
      <InternalLink RefPartnerSideA="1d008df3-1533-491a-bfb0-e05f61a16c53" RefPartnerSideB="8b0902ce-e7ab-421e-ab75-770df99554cd" Name="HLink1" />
      <InternalLink RefPartnerSideA="1d008df3-1533-491a-bfb0-e05f61a16c53" RefPartnerSideB="7100c7b6-9ea7-4e5b-9a64-3ace67d59b1e" Name="HLink2" />
    </InternalElement>

    <InternalElement Name="Attacker" ID="Attacker" RefBaseSystemUnitPath="AssetOfICS/User">
      <Attribute Name="HumanErrorEstimationPercentage" AttributeDataType="xs:string">
        <Value>100</Value>
      </Attribute>
      <ExternalInterface Name="IO" ID="36119a16-4bfe-4bf8-ad15-99391e9eaf38" RefBaseClassPath="ConnectionBetnAssets/User based" />
      <InternalLink RefPartnerSideA="36119a16-4bfe-4bf8-ad15-99391e9eaf38" RefPartnerSideB="b6fecd68-6843-4fe6-825e-79a9c71cfee9" Name="LLink" />
      <InternalLink RefPartnerSideA="36119a16-4bfe-4bf8-ad15-99391e9eaf38" RefPartnerSideB="9901a662-edd9-4eac-8f00-97be82bb83cf" Name="LLink1" />
    </InternalElement>
  </InstanceHierarchy>

  <InstanceHierarchy Name="Vulnerabilities">
    <Version>0</Version>
    <InternalElement Name="(V1) CVE-2024-50684" ID="V1" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="9b924c3f-425a-4a8b-8531-cca016ddef08">
          <Value>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.6568</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.2702</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV1" ID="911514f8-0f3b-4196-85f0-95efbd8fce81" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="911514f8-0f3b-4196-85f0-95efbd8fce81" RefPartnerSideB="bbba14d7-f291-4974-b4c0-53a29bd7f33d" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V2) CVE-2024-50691" ID="V2" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="eedd89d6-149a-4239-8ffe-910783a06aa1">
          <Value>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.8064</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.2702</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV2" ID="07c071d3-c63b-422e-9e6d-122713068187" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="07c071d3-c63b-422e-9e6d-122713068187" RefPartnerSideB="bbba14d7-f291-4974-b4c0-53a29bd7f33d" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V3) CVE-2024-50688" ID="V3" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="f56ad292-4e7f-4b4e-9351-03f82593c51c">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.9148</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV3" ID="9127963f-a666-4252-baa5-a8287b4ce75c" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="9127963f-a666-4252-baa5-a8287b4ce75c" RefPartnerSideB="bbba14d7-f291-4974-b4c0-53a29bd7f33d" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V4) CVE-2024-50690" ID="V4" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="2fd94ea4-acb0-4f18-b3ee-5cf8debb51dc">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.3916</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV4" ID="fc2b3b23-5dec-4004-8f2e-14f7b12355ec" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="fc2b3b23-5dec-4004-8f2e-14f7b12355ec" RefPartnerSideB="2587557e-3138-4d47-bece-f6c00aec4d42" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V5) CVE-2024-50692" ID="V5" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="6a5116fc-ae75-447e-8626-151fe2c30991">
          <Value>CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.3916</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.2516</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV5" ID="2587557e-3138-4d47-bece-f6c00aec4d42" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="2587557e-3138-4d47-bece-f6c00aec4d42" RefPartnerSideB="8a2a4f44-9212-433a-8930-b4634c152395" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V6) CVE-2024-50685" ID="V6" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="6c9681e4-d6ab-4a26-80c7-5ee48ce55c55">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.8064</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV6" ID="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" RefPartnerSideB="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" Name="Link" />
      <InternalLink RefPartnerSideA="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" RefPartnerSideB="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" Name="Link1" />
      <InternalLink RefPartnerSideA="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" RefPartnerSideB="ad72f0f2-b63d-4533-8bbe-ad506898d36a" Name="Link2" />
      <InternalLink RefPartnerSideA="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" RefPartnerSideB="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" Name="Link3" />
      <InternalLink RefPartnerSideA="9b82a3e4-723a-47b1-ae10-6fc02cdfd911" RefPartnerSideB="8a2a4f44-9212-433a-8930-b4634c152395" Name="Link4" />
    </InternalElement>

    <InternalElement Name="(V7) CVE-2024-50686" ID="V7" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="463e6bfd-53bc-420b-8a96-40b1e4d71b66">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.8064</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV7" ID="cc102c11-c2f8-4b95-9701-2c975f5ea63b" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="cc102c11-c2f8-4b95-9701-2c975f5ea63b" RefPartnerSideB="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" Name="Link" />
      <InternalLink RefPartnerSideA="cc102c11-c2f8-4b95-9701-2c975f5ea63b" RefPartnerSideB="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" Name="Link1" />
      <InternalLink RefPartnerSideA="cc102c11-c2f8-4b95-9701-2c975f5ea63b" RefPartnerSideB="ad72f0f2-b63d-4533-8bbe-ad506898d36a" Name="Link2" />
      <InternalLink RefPartnerSideA="cc102c11-c2f8-4b95-9701-2c975f5ea63b" RefPartnerSideB="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" Name="Link3" />
      <InternalLink RefPartnerSideA="cc102c11-c2f8-4b95-9701-2c975f5ea63b" RefPartnerSideB="8a2a4f44-9212-433a-8930-b4634c152395" Name="Link4" />
    </InternalElement>

    <InternalElement Name="(V8) CVE-2024-50687" ID="V8" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="1ce80dc0-54ad-43fc-9703-b3fcc4769f19">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.8064</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV8" ID="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" RefPartnerSideB="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" Name="Link" />
      <InternalLink RefPartnerSideA="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" RefPartnerSideB="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" Name="Link1" />
      <InternalLink RefPartnerSideA="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" RefPartnerSideB="ad72f0f2-b63d-4533-8bbe-ad506898d36a" Name="Link2" />
      <InternalLink RefPartnerSideA="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" RefPartnerSideB="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" Name="Link3" />
      <InternalLink RefPartnerSideA="3d056ff8-488c-4bdf-9321-633e1c1f5ea6" RefPartnerSideB="8a2a4f44-9212-433a-8930-b4634c152395" Name="Link4" />
    </InternalElement>

    <InternalElement Name="(V9) CVE-2024-50689" ID="V9" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="5d07c4a3-0030-4505-af6f-cbae8832d5d0">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.8064</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV9" ID="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" RefPartnerSideB="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" Name="Link" />
      <InternalLink RefPartnerSideA="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" RefPartnerSideB="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" Name="Link1" />
      <InternalLink RefPartnerSideA="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" RefPartnerSideB="ad72f0f2-b63d-4533-8bbe-ad506898d36a" Name="Link2" />
      <InternalLink RefPartnerSideA="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" RefPartnerSideB="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" Name="Link3" />
      <InternalLink RefPartnerSideA="f0d40c84-34eb-489a-b7aa-04bab1ff24c0" RefPartnerSideB="8a2a4f44-9212-433a-8930-b4634c152395" Name="Link4" />
    </InternalElement>

    <InternalElement Name="(V10) CVE-2024-50693" ID="V10" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="383554d8-1e0f-4909-8710-3c47484ff095">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.8064</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV10" ID="adfd6ccf-c3c7-4929-b69c-1d5232b48617" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="adfd6ccf-c3c7-4929-b69c-1d5232b48617" RefPartnerSideB="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" Name="Link" />
      <InternalLink RefPartnerSideA="adfd6ccf-c3c7-4929-b69c-1d5232b48617" RefPartnerSideB="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" Name="Link1" />
      <InternalLink RefPartnerSideA="adfd6ccf-c3c7-4929-b69c-1d5232b48617" RefPartnerSideB="ad72f0f2-b63d-4533-8bbe-ad506898d36a" Name="Link2" />
      <InternalLink RefPartnerSideA="adfd6ccf-c3c7-4929-b69c-1d5232b48617" RefPartnerSideB="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" Name="Link3" />
      <InternalLink RefPartnerSideA="adfd6ccf-c3c7-4929-b69c-1d5232b48617" RefPartnerSideB="8a2a4f44-9212-433a-8930-b4634c152395" Name="Link4" />
    </InternalElement>

    <InternalElement Name="(V11) CVE-2024-50694" ID="V11" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="7630aae0-d981-457c-9f90-84b770292e4e">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.9148</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV11" ID="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="12ec1fc3-5b14-4fcb-8ac9-7fbb0102eee5" RefPartnerSideB="b64a1153-5840-4a28-9027-ee37f10c305c" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V12) CVE-2024-50695" ID="V12" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="3b064d67-2d20-4075-878a-0357762b93e1">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.9148</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV12" ID="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="3a25cc96-4f73-4b79-9b4d-a211304e6e9f" RefPartnerSideB="b64a1153-5840-4a28-9027-ee37f10c305c" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V13) CVE-2024-50697" ID="V13" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="8826fead-028a-42b7-b411-9579d6feba9c">
          <Value>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.9148</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.2702</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV13" ID="ad72f0f2-b63d-4533-8bbe-ad506898d36a" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="ad72f0f2-b63d-4533-8bbe-ad506898d36a" RefPartnerSideB="b64a1153-5840-4a28-9027-ee37f10c305c" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V14) CVE-2024-50698" ID="V14" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="13a46011-b53c-40d2-a9a9-d121102bed3d">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.9148</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV14" ID="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="146a3159-0fff-4f8d-b3a5-b7d6ead3f4fc" RefPartnerSideB="b64a1153-5840-4a28-9027-ee37f10c305c" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V15) CVE-2024-50696" ID="V15" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="c0139d70-cdb1-4574-a6f2-c7d96e9cf4ae">
          <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</Value>
        </Attribute>
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.56</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV15" ID="8a2a4f44-9212-433a-8930-b4634c152395" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="8a2a4f44-9212-433a-8930-b4634c152395" RefPartnerSideB="b64a1153-5840-4a28-9027-ee37f10c305c" Name="Link" />
    </InternalElement>

    <InternalElement Name="(V16) Dynamic Load Attack" ID="V16" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
        <Attribute Name="CVE" AttributeDataType="xs:string" />
        <Attribute Name="CVSS" AttributeDataType="xs:string" ID="8f780383-62f9-4408-81a5-e7d285bfa670" />
        <Attribute Name="Attack Name" AttributeDataType="xs:string" />
        <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
          <Value>0.9148</Value>
        </Attribute>
        <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
          <Value>1</Value>
        </Attribute>
        <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
          <Value>0.4729</Value>
        </Attribute>
      </Attribute>
      <ExternalInterface Name="ToV16" ID="099916f1-a2df-4241-a6b1-5912fe33cb85" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="099916f1-a2df-4241-a6b1-5912fe33cb85" RefPartnerSideB="cb07ea86-fba4-43e0-8b9b-7fbf852b4d5c" Name="Link" />
    </InternalElement>
  </InstanceHierarchy>

  <InstanceHierarchy Name="Hazards" ID="a8f06f3b-9aa4-4e84-96d9-fc8f22cf4109">
    <Version>1.0.0</Version>
    <InternalElement Name="(H1) Data Leakage" ID="H1_Data_Leakage" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH1" ID="5cea00b2-17c7-4c88-a6a5-68dbce257bf5" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="5cea00b2-17c7-4c88-a6a5-68dbce257bf5" RefPartnerSideB="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" Name="Link" />
    </InternalElement>
    <InternalElement Name="(H2) Hijack Other Devices" ID="H2_Hijack_Other_Devices" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH2" ID="2cfaa84f-2283-4ba1-b854-67062f08337f" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="2cfaa84f-2283-4ba1-b854-67062f08337f" RefPartnerSideB="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" Name="Link" />
    </InternalElement>
    <InternalElement Name="(H3) Cyber-Physical Ransomware" ID="H3_Cyber_Physical_Ransomware" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH3" ID="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" RefPartnerSideB="2cd7055d-a75d-4a97-bee6-65ebae7cecda" Name="Link" />
      <InternalLink RefPartnerSideA="93a8ff2b-3729-49c5-9f8b-f67b4c6831df" RefPartnerSideB="4ee29329-32de-46a6-ba7f-c80207d2767a" Name="Link1" />
    </InternalElement>
    <InternalElement Name="(H4) Alter Energy Production" ID="H4_Alter_Energy_Production" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH4" ID="2cd7055d-a75d-4a97-bee6-65ebae7cecda" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="2cd7055d-a75d-4a97-bee6-65ebae7cecda" RefPartnerSideB="7100c7b6-9ea7-4e5b-9a64-3ace67d59b1e" Name="Link" />
    </InternalElement>
    <InternalElement Name="(H5) Load Shedding" ID="H5_Load_Shedding" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH5" ID="7100c7b6-9ea7-4e5b-9a64-3ace67d59b1e" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="7100c7b6-9ea7-4e5b-9a64-3ace67d59b1e" RefPartnerSideB="dd68545e-5878-4bae-ad26-90aba73e4ff2" Name="Link" />
    </InternalElement>
    <InternalElement Name="(H6) Emergency Equipment Failure" ID="H6_Emergency_Equipment_Failure" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH6" ID="4ee29329-32de-46a6-ba7f-c80207d2767a" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="4ee29329-32de-46a6-ba7f-c80207d2767a" RefPartnerSideB="dd68545e-5878-4bae-ad26-90aba73e4ff2" Name="Link" />
    </InternalElement>
    <InternalElement Name="(H7) Grid Instability" ID="H7_Grid_Instability" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH7" ID="8b0902ce-e7ab-421e-ab75-770df99554cd" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="8b0902ce-e7ab-421e-ab75-770df99554cd" RefPartnerSideB="dd68545e-5878-4bae-ad26-90aba73e4ff2" Name="Link" />
    </InternalElement>
    <InternalElement Name="(H8) Power Outage" ID="H8_Power_Outage" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <ExternalInterface Name="ToH8" ID="dd68545e-5878-4bae-ad26-90aba73e4ff2" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
    </InternalElement>
  </InstanceHierarchy>

  <InterfaceClassLib Name="ConnectionBetnAssets">
    <Version>0</Version>
    <InterfaceClass Name="Network based" />
    <InterfaceClass Name="Logic based" />
    <InterfaceClass Name="User based" />
    <InterfaceClass Name="HazardRef" />
    <InterfaceClass Name="VulnerabilityRef" />
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

Inputs:

Architecture Explanation:
{arch_explanation}

Threat Model:
{threat_model}

Attack Tree:
{attack_tree}

Output Requirements:

- Produce syntactically valid AutomationML XML representing the system architecture and security model elements.
- Populate attribute values descriptively based on the provided input data.
- For vulnerabilities without known CVEs, assign CVE the value "N/A" and provide a synthetic CVSS vector reflecting the vulnerability description as the CVSS attribute.
- Compute the Probability of Exposure attribute from the CVSS vector as Probability of Exposure = AV * AC * PR * UI, where AV, AC, PR, and UI come from the CVSS vector.
- For vulnerabilities with known CVEs, assign the EPSS score (0 to 1) to both the EPSS attribute and Probability of Exposure attribute.
- Do not assign EPSS scores to vulnerabilities without known CVEs.
- Estimate FailureRatePerHour (0 to 1) for assets when not explicitly provided.
- Estimate Impact Rating (0 to 1) for assets and hazards based on threat model and attack tree criticality.
- Include all required `InternalElement` and `InternalLink` elements reflecting relationships and attack paths.
- The Attacker must link to an Asset, Vulnerability, or Hazard.
- The Goal must link to an Asset, Vulnerability, or Hazard.
- Ensure well-formed XML with proper indentation.
- Output ONLY valid AutomationML XML file content starting with:

<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="cps.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">

Generate the AutomationML file now without any explanations or extra text.

"""
    return prompt
 

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

