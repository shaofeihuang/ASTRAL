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


def create_aml_prompt(arch_explanation, threat_model, attack_tree):
    prompt = f"""
You are an expert in AutomationML (AML) file generation according to the IEC 62714 standard.

Your task is to generate an AutomationML representation of the cyber-physical system architecture with integrated security modelling elements based on the provided architectural explanation, threat model, and attack tree.

Strictly follow these instructions:

1. Represent Core Elements:
   - Model Assets as `InternalElement` objects with attributes including `Vendor`, `Version`, `FailureRatePerHour`, `Impact Rating`, and `Date of first use`.
   - Model Vulnerabilities as `InternalElement` objects with attributes `CVE`, `CVSS`, `Attack Name`, `Probability of Impact`, `Probability of Exposure`, `Probability of Mitigation`, and optionally `EPSS`.
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

5. Output Requirements:
Produce syntactically valid AutomationML XML representing the system architecture and security model elements.
	- Populate attribute values descriptively based on the provided input data.
	- For vulnerabilities without known CVEs, assign CVE the value "Proxy Vulnerability" and provide a proxy CVSS vector reflecting the vulnerability description as the CVSS attribute.
	- Compute the Probability of Exposure attribute based on the CVSS vector using the formula: .
	- For vulnerabilities linked to CVEs, use the EPSS score (ranging from 0 to 1) as both the EPSS and Probability of Exposure attributes if available.
	- Estimate FailureRatePerHour (between 0 and 1) for assets when not explicitly provided, using typical values for comparable components.
	- Estimate Impact Rating (between 0 and 1) for assets and hazards based on analysis of the threat model and attack tree; higher values indicate greater criticality.
	- Include all required InternalElement and InternalLink elements to accurately reflect asset, vulnerability, hazard relationships, and attack paths derived from the threat model and attack tree.
Use the following example AutomationML file as a reference for structure, conventions, and common patterns.

<?xml version="1.0" encoding="utf-8"?>
<CAEXFile SchemaVersion="3.0" FileName="BlackEnergy.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">
  <InstanceHierarchy Name="BlackEnergy Example">
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
      <InternalLink RefPartnerSideA="629f5ad5-bf5f-43c1-b20f-89ae3b71c3f8" RefPartnerSideB="e1689a99-4f83-4ed6-87ee-0b188d4fb7a0" Name="InternalLink" />
      <InternalLink RefPartnerSideA="629f5ad5-bf5f-43c1-b20f-89ae3b71c3f8" RefPartnerSideB="95105044-cb13-409a-b8f9-b1660b1b3c7f" Name="InternalLink" />
      <InternalLink RefPartnerSideA="629f5ad5-bf5f-43c1-b20f-89ae3b71c3f8" RefPartnerSideB="7b556454-e105-48de-be58-f2822060eeb3" Name="Link1" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Security" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Process" />
    </InternalElement>
    
    <InternalElement Name="IT Workstation" ID="[A02] IT_Workstation" RefBaseSystemUnitPath="AssetOfICS/Hardware/Process device/Workstation">
      <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
        <Attribute Name="Vendor" AttributeDataType="xs:string" />
        <Attribute Name="Part" AttributeDataType="xs:string" />
        <Attribute Name="Product" AttributeDataType="xs:string" />
        <Attribute Name="Version" AttributeDataType="xs:string" />
        <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float">
          <Value>1.48254E-05</Value>
        </Attribute>
        <Attribute Name="Impact Rating" AttributeDataType="xs:float">
          <Value>0.227272727</Value>
        </Attribute>
        <Attribute Name="Date of first use" AttributeDataType="xs:string" />
      </Attribute>
      <ExternalInterface Name="toHazard" ID="43422fd2-2a29-4185-a83e-acfde36f1cad" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <ExternalInterface Name="toVulnerability" ID="de6258a7-8d39-4711-8414-f866f4999249" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="43422fd2-2a29-4185-a83e-acfde36f1cad" RefPartnerSideB="e1689a99-4f83-4ed6-87ee-0b188d4fb7a0" Name="InternalLink" />
      <InternalLink RefPartnerSideA="de6258a7-8d39-4711-8414-f866f4999249" RefPartnerSideB="859f5926-248e-43b7-88b5-184f7d4ed9c7" Name="InternalLink" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Security" />
      <RoleRequirements RefBaseRoleClassPath="Requirements/Process" />
    </InternalElement>

    <InternalElement Name="User" ID="[U01] User" RefBaseSystemUnitPath="AssetOfICS/User">
      <Attribute Name="HumanErrorEstimationPercentage" AttributeDataType="xs:string">
        <Value>5</Value>
      </Attribute>
      <ExternalInterface Name="toHazard" ID="870bb67c-df05-42e3-9bb8-1783bdb2e5e6" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <ExternalInterface Name="toVulnerability" ID="74070941-2c10-46c7-a846-1cc17ccec0cc" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="870bb67c-df05-42e3-9bb8-1783bdb2e5e6" RefPartnerSideB="26dc9b7a-8ef2-40c3-bd8d-1de83035f170" Name="InternalLink" />
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
      <InternalLink RefPartnerSideA="26dc9b7a-8ef2-40c3-bd8d-1de83035f170" RefPartnerSideB="65b98fc9-22ea-4b35-9ad5-a04984dea1f7" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[H02] Disable backup power supply" ID="H2_Disable_Backup_PS" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <Attribute Name="Name" AttributeDataType="xs:string" />
      <Attribute Name="Probability" AttributeDataType="xs:string" />
      <Attribute Name="Impact Rating" AttributeDataType="xs:float">
        <Value>0.227272727</Value>
      </Attribute>
      <ExternalInterface Name="ToHaz02" ID="7b556454-e105-48de-be58-f2822060eeb3" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="7b556454-e105-48de-be58-f2822060eeb3" RefPartnerSideB="17a0a47e-1a0e-4789-9310-3e7631f96417" Name="InternalLink" />
    </InternalElement>
    
    <InternalElement Name="[H03] DoS telephone lines" ID="H3_DoS_Telephone_Lines" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <Attribute Name="Impact Rating" AttributeDataType="xs:float">
        <Value>0.227272727</Value>
      </Attribute>
      <ExternalInterface Name="ToHaz03" ID="eb997142-db18-4ef4-b338-d064afcf96e6" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="eb997142-db18-4ef4-b338-d064afcf96e6" RefPartnerSideB="17a0a47e-1a0e-4789-9310-3e7631f96417" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[H04] Disrupt OT" ID="H4_Disrupt_OT" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <Attribute Name="Impact Rating" AttributeDataType="xs:float">
        <Value>0.318181818</Value>
      </Attribute>
      <ExternalInterface Name="ToHaz04" ID="17a0a47e-1a0e-4789-9310-3e7631f96417" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
      <InternalLink RefPartnerSideA="17a0a47e-1a0e-4789-9310-3e7631f96417" RefPartnerSideB="95105044-cb13-409a-b8f9-b1660b1b3c7f" Name="InternalLink" />
    </InternalElement>
    
    <InternalElement Name="[H05] Disable electrical supply" ID="H5_Disable_Electrical_Supply" RefBaseSystemUnitPath="HazardforSystem/Hazard">
      <Attribute Name="Impact Rating" AttributeDataType="xs:float">
        <Value>0.386363636</Value>
      </Attribute>
      <ExternalInterface Name="ToHaz05" ID="95105044-cb13-409a-b8f9-b1660b1b3c7f" RefBaseClassPath="ConnectionBetnAssets/HazardRef" />
    </InternalElement>
  </InstanceHierarchy>

  <InstanceHierarchy Name="Vulnerabilities">
    <Version>0</Version>
    <InternalElement Name="[V01] Powerpoint 0-Day" ID="V1" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string">
        <Value>CVE-2014-4114</Value>
      </Attribute>
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="34643025-7ad6-4dc0-a9aa-833394f9f835">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V1</Value>
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

    <InternalElement Name="[V02] MS-Word 0-Day" ID="V2" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string">
        <Value>CVE-2014-1761</Value>
      </Attribute>
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="48e8cafe-2b1d-486c-9fc0-9c919f38c1d4">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Description>V2</Description>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>      
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.9294</Value>
      </Attribute>
      <ExternalInterface Name="ToV2" ID="65b98fc9-22ea-4b35-9ad5-a04984dea1f7" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="65b98fc9-22ea-4b35-9ad5-a04984dea1f7" RefPartnerSideB="de6258a7-8d39-4711-8414-f866f4999249" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V03] Malware downloader" ID="V3" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="1a81ab76-c5c6-46b6-bba5-50b85fdecdf5">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V3</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.3060</Value>
      </Attribute>
      <ExternalInterface Name="ToV3" ID="859f5926-248e-43b7-88b5-184f7d4ed9c7" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="859f5926-248e-43b7-88b5-184f7d4ed9c7" RefPartnerSideB="d1e0f082-13e8-4ce8-9751-5e935992261c" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V04] Masquerading (driver)" ID="V4" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="c005726e-3386-4882-948b-2f32deba68c7">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V4</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.2232</Value>
      </Attribute>
      <ExternalInterface Name="ToV4" ID="d1e0f082-13e8-4ce8-9751-5e935992261c" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="d1e0f082-13e8-4ce8-9751-5e935992261c" RefPartnerSideB="147e1fd0-8ff9-4c2f-92ed-d427722a81a3" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V05] Priv Esc" ID="V5" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="eb8d9b5c-3ff5-4a8d-9d22-7cffb8b9ad15">
        <Value>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V5</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.2232</Value>
      </Attribute>
      <ExternalInterface Name="ToV5" ID="147e1fd0-8ff9-4c2f-92ed-d427722a81a3" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="147e1fd0-8ff9-4c2f-92ed-d427722a81a3" RefPartnerSideB="ff1f16c6-2baa-42eb-b719-da9e1c5b2ee8" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V06] Install KillDisc malware" ID="V6" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="14fa7a55-7101-408a-bda8-e8fff1f9f617">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V6</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.2232</Value>
      </Attribute>
      <ExternalInterface Name="ToV6" ID="ff1f16c6-2baa-42eb-b719-da9e1c5b2ee8" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="ff1f16c6-2baa-42eb-b719-da9e1c5b2ee8" RefPartnerSideB="fe413177-afd9-4a14-bb53-e6dbf577fece" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V07] Install RAT" ID="V7" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="776744a4-5015-4b86-bbe9-750d0fce781f">
        <Value>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V7</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.2232</Value>
      </Attribute>
      <ExternalInterface Name="ToV7" ID="fe413177-afd9-4a14-bb53-e6dbf577fece" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="fe413177-afd9-4a14-bb53-e6dbf577fece" RefPartnerSideB="6e89716a-bc8d-40c3-bf26-331b3e8afe40" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V08] SSH Backdoor Persistence" ID="V8" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="d5fe4b51-7633-4dcf-b155-733577014e77">
        <Value>CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V8</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.0555</Value>
      </Attribute>
      <ExternalInterface Name="ToV8" ID="6e89716a-bc8d-40c3-bf26-331b3e8afe40" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="6e89716a-bc8d-40c3-bf26-331b3e8afe40" RefPartnerSideB="4c532fb3-c73b-4a55-bb9f-64628c815348" Name="InternalLink" />
    </InternalElement>

    <InternalElement Name="[V09] Lateral Movement (Recon)" ID="V9" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="7351854d-9cb5-4466-aafd-f45252a50f8f">
        <Value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V9</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.2200</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.4729</Value>
      </Attribute>
      <ExternalInterface Name="ToV9" ID="4c532fb3-c73b-4a55-bb9f-64628c815348" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="4c532fb3-c73b-4a55-bb9f-64628c815348" RefPartnerSideB="563c778e-246c-40ea-8372-451569102a1f" Name="InternalLink" />
    </InternalElement>
    
    <InternalElement Name="[V10] Exfiltrate info to C2 Server" ID="V10" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="0a5831ee-9a91-4b61-94f6-abf33b969e2d">
        <Value>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V10</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.5600</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.3449</Value>
      </Attribute>
      <ExternalInterface Name="ToV10" ID="563c778e-246c-40ea-8372-451569102a1f" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="563c778e-246c-40ea-8372-451569102a1f" RefPartnerSideB="933ca543-ac77-4916-a4fb-80e4287e6eff" Name="InternalLink" />
    </InternalElement>
    
    <InternalElement Name="[V11] Access VPN" ID="V11" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
      <Attribute Name="CVE" AttributeDataType="xs:string" />
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="a8fe3802-72fe-43c8-9a59-d7ae1baeec67">
        <Value>CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</Value>
      </Attribute>
      <Attribute Name="Attack Name" AttributeDataType="xs:string">
        <Value>V11</Value>
      </Attribute>
      <Attribute Name="Probability of Impact" AttributeDataType="xs:string">
        <Value>0.9148</Value>
      </Attribute>
      <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string">
        <Value>1</Value>
      </Attribute>
      <Attribute Name="Probability of Exposure" AttributeDataType="xs:string">
        <Value>0.1502</Value>
      </Attribute>
      <ExternalInterface Name="ToV11" ID="933ca543-ac77-4916-a4fb-80e4287e6eff" RefBaseClassPath="ConnectionBetnAssets/VulnerabilityRef" />
      <InternalLink RefPartnerSideA="933ca543-ac77-4916-a4fb-80e4287e6eff" RefPartnerSideB="6e05a84b-54d8-4d39-a98d-819ac4c0a435" Name="InternalLink" />
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
      <Attribute Name="CVSS" AttributeDataType="xs:string" ID="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:T/RC:R" />
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

Output requirements:
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

