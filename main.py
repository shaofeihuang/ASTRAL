import os
import json
import re
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv
from mistralai import Mistral

load_dotenv()

model_token_limits = {
    "pixtral-12b-latest": {"default": 64000, "max": 128000},
    "ministral-8b-latest": {"default": 64000, "max": 128000},
    "mistral-medium-latest": {"default": 64000, "max": 128000},
    "mistral-large-latest": {"default": 64000, "max": 128000},
    "mistral-small-latest": {"default": 24000, "max": 32000},
    "magistral-small-latest": {"default": 32000, "max": 40000},
    "magistral-medium-latest": {"default": 32000, "max": 40000},
}


def get_api_key():
    default_key = os.getenv("MISTRAL_API_KEY", "")
    return st.sidebar.text_input("Mistral API Key", value=default_key, type="password")


def get_model_choice():
    return st.sidebar.selectbox(
        "Select the model you would like to use:",
        list(model_token_limits.keys()),
        key="selected_model",
        help=(
            "Select a suitable model. Larger models may provide better results but can be slower and more costly."
        ),
    )


def get_system_context():
    return st.sidebar.text_input(
        "Cyber-Physical System Context",
        value="Cyber-Physical System",
        placeholder="e.g. Solar PV inverter, ICS, etc.",
        help="Describe the specific cyber-physical system context for tailored threat modelling."
    )


def call_mistral(api_key, prompt_text: str, image_bytes: bytes, model_name: str, max_tokens: int, response_as_json: bool = False):
    client = Mistral(api_key=api_key)
    params = {
        "model": model_name,
        "messages": [
            {"role": "user", "content": prompt_text, "image": image_bytes}
        ],
        "max_tokens": max_tokens,
    }
    if response_as_json:
        params["response_format"] = {"type": "json_object"}
    
    response = client.chat.complete(**params)
    content = response.choices[0].message.content
    
    if response_as_json:
        import json
        return json.loads(content)
    else:
        return content

def clean_json_response(response_text):
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    return response_text.strip()


def tm_json_to_markdown(threat_model, improvement_suggestions):
    markdown_output = "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
    
    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"
    
    return markdown_output


def at_json_to_markdown(arch_explanation, threat_model):
    markdown_output = "## Architecture Explanation\n\n"
    
    markdown_output += arch_explanation + "\n\n"
    
    markdown_output += "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
    
    return markdown_output

def dread_json_to_markdown(dread_assessment):
    # Create a clean Markdown table with proper spacing
    markdown_output = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|------------|----------|------------------|-----------------|----------------|----------------|-----------------|------------|\n"
    
    try:
        # Access the list of threats under the "Risk Assessment" key
        threats = dread_assessment.get("Risk Assessment", [])
        
        # If there are no threats, add a message row
        if not threats:
            markdown_output += "| No threats found | Please generate a threat model first | - | - | - | - | - | - |\n"
            return markdown_output
            
        for threat in threats:
            # Check if threat is a dictionary
            if isinstance(threat, dict):
                # Get values with defaults
                threat_type = threat.get('Threat Type', 'N/A')
                scenario = threat.get('Scenario', 'N/A')
                damage_potential = threat.get('Damage Potential', 0)
                reproducibility = threat.get('Reproducibility', 0)
                exploitability = threat.get('Exploitability', 0)
                affected_users = threat.get('Affected Users', 0)
                discoverability = threat.get('Discoverability', 0)
                
                # Calculate the Risk Score
                risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5
                
                # Escape any pipe characters in text fields to prevent table formatting issues
                threat_type = str(threat_type).replace('|', '\\|')
                scenario = str(scenario).replace('|', '\\|')
                
                # Ensure scenario text doesn't break table formatting by removing newlines
                scenario = scenario.replace('\n', ' ').replace('\r', '')
                
                # Add the row to the table with proper formatting
                markdown_output += f"| {threat_type} | {scenario} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                # Skip non-dictionary entries and log a warning
                markdown_output += "| Invalid threat | Threat data is not in the correct format | - | - | - | - | - | - |\n"
    except Exception as e:
        # Add a note about the error and a placeholder row
        markdown_output += "| Error | An error occurred while processing the DREAD assessment | - | - | - | - | - | - |\n"
    
    # Add a blank line after the table for better rendering
    markdown_output += "\n"
    return markdown_output


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



def convert_tree_to_mermaid(tree_data):
    mermaid_lines = ["graph BT"]
    
    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]
        
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'
        
        mermaid_lines.append(f'    {node_id}[{node_label}]')
        
        if parent_id:
#            mermaid_lines.append(f'    {parent_id} --> {node_id}')
            mermaid_lines.append(f'    {node_id} --> {parent_id}')
        
        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)
    
    for root_node in tree_data["nodes"]:
        process_node(root_node)
    
    return "\n".join(mermaid_lines)


def create_attack_tree_schema():
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "$ref": "#/$defs/node"
                        }
                    }
                },
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node"
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal"
                            },
                            "children": {
                                "type": "array",
                                "items": {
                                    "$ref": "#/$defs/node"
                                }
                            }
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False
            },
            "strict": True
        }
    }


def get_attack_tree(api_key, selected_model, prompt, system_context):
    client = Mistral(api_key=api_key)
    system_prompt = create_attack_tree_prompt(system_context)
    response = client.chat.complete(
        model=selected_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )
    try:
        cleaned_response = clean_json_response(response.choices[0].message.content)
        tree_data = json.loads(cleaned_response)
        return convert_tree_to_mermaid(tree_data)
    except json.JSONDecodeError:
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(response.choices[0].message.content)


def extract_mermaid_code(text):
    mermaid_pattern = r'```mermaid\s*(graph[\s\S]*?)```'
    match = re.search(mermaid_pattern, text, re.MULTILINE)
    
    if not match:
        code_pattern = r'```\s*(graph[\s\S]*?)```'
        match = re.search(code_pattern, text, re.MULTILINE)
    
    if match:
        code = match.group(1).strip()
    else:
        code = text.strip()
    
    if not code.startswith('graph '):
        if 'graph ' in code:
            code = code[code.find('graph '):]
        else:
            return text

    code = clean_mermaid_syntax(code)
    
    return code

def clean_mermaid_syntax(code):
    code = re.sub(r'(\w+|\]|\)|\})(-->|==>|-.->)(\w+|\[|\(|\{)', r'\1 \2 \3', code)
    
    def fix_node_brackets(match):
        node_id = match.group(1)
        if not any(c in node_id for c in '[](){}'):
            return f'{node_id}[{node_id}]'
        return node_id
    code = re.sub(r'(?:^|\s)(\w+)(?:\s|$)', fix_node_brackets, code)
    
    def quote_node_labels(match):
        label = match.group(1)
        if ' ' in label and not label.startswith('"'):
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', quote_node_labels, code)
    
    def fix_parentheses(match):
        label = match.group(1)
        if '(' in label or ')' in label:
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', fix_parentheses, code)
    
    code = code.replace('\r\n', '\n').strip()
    
    return code


def mermaid(code: str, height: int = 500) -> None:
    components.html(
        f"""
        <pre class="mermaid" style="height: {height}px;">
            {code}
        </pre>

        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true }});
        </script>
        """,
        height=height,
    )


def get_dread_assessment(api_key, selected_model, prompt):
    client = Mistral(api_key=api_key)

    response = client.chat.complete(
        model=selected_model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        dread_assessment = {}

    return dread_assessment

    









def main():
    api_key = get_api_key()
    selected_model = get_model_choice()
    max_tokens = model_token_limits[selected_model]["default"]
    system_context = get_system_context()

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Architecture", "Threat Model", "Attack Tree", "AutomationML", "DREAD", "Mitigation"])

    with tab1:
        st.title("Architecture-based Threat Modelling with Mistral AI")

        st.markdown("""---""")

        if not api_key:
            st.sidebar.warning("Please enter your Mistral API key.")
            st.stop()

        uploaded_file = st.file_uploader(
            "Upload Architecture / Data Flow Diagram (DFD) Image", type=["png", "jpg", "jpeg", "bmp", "gif"]
        )

        if uploaded_file is not None:
            image_bytes = uploaded_file.read()
            st.image(image_bytes, caption="Uploaded Image", width="stretch")
            arch_expl_prompt = create_arch_expl_prompt(system_context)

        # Generate Architectural Explanation Button
        if st.button("Generate Architectural Explanation", key="gen_arch_exp"):
            with st.spinner("Generating architectural explanation..."):
                try:
                    model_output = call_mistral(
                        api_key, arch_expl_prompt, image_bytes, selected_model, max_tokens, response_as_json=False
                    )
                    st.session_state['arch_explanation'] = model_output
                except Exception as e:
                    st.error(f"Failed to generate architectural explanation: {str(e)}")

        # Display Architectural Explanation if available
        if 'arch_explanation' in st.session_state:
            st.subheader("Architectural Explanation")
            st.write(st.session_state['arch_explanation'])
            st.download_button(
                label="Download Architectural Explanation",
                data=st.session_state['arch_explanation'],
                file_name="arch_explanation.md",
                mime="text/markdown",
            )
            additional_detail = st.text_area(
                "Add Additional Details (Optional)",
                value="",
                placeholder="Type extra architectural specifics here...",
                height=150,
            )
            # Re-Generate Architectural Explanation Button
            if st.button("Re-Generate Architectural Explanation", key="regen_arch_exp"):
                with st.spinner("Generating architectural explanation..."):
                    try:
                        model_output = call_mistral(
                            api_key, arch_expl_prompt + "\n" + additional_detail.strip(), image_bytes, selected_model, max_tokens, response_as_json=False
                        )
                        st.session_state['arch_explanation'] = model_output
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to generate architectural explanation: {str(e)}")


    with tab2:
        st.markdown("""
        A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
        understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE-LM methodology.
        """)
        st.markdown("""---""")
        threat_model_prompt = create_threat_model_prompt(system_context)
        
        # Generate STRIDE-LM Threat Model Button
        if st.button("Generate STRIDE-LM Threat Model", key="gen_threat_model"):
            with st.spinner("Generating STRIDE-LM threat model..."):
                try:
                    model_output = call_mistral(
                        api_key, threat_model_prompt, image_bytes, selected_model, max_tokens, response_as_json=True
                    )
                    st.session_state['threat_model'] = model_output.get("threat_model", [])
                    st.session_state['improvement_suggestions'] = model_output.get("improvement_suggestions", [])
                except Exception as e:
                    st.error(f"Failed to generate threat model: {str(e)}")

        # Display Threat Model if available
        if 'threat_model' in st.session_state:
            markdown_output = tm_json_to_markdown(
                st.session_state['threat_model'],
                st.session_state.get('improvement_suggestions', [])
            )
            st.subheader("Generated STRIDE-LM Threat Model")
            st.markdown(markdown_output)
            st.download_button(
                label="Download Threat Model",
                data=markdown_output,
                file_name="threat_model.md",
                mime="text/markdown",
            )

    with tab3:
        st.markdown("""
        Attack trees are a structured way to analyse the security of a system. They represent potential attack scenarios in a hierarchical format, 
        with the ultimate goal of an attacker at the root and various paths to achieve that goal as branches. This helps in understanding system 
        vulnerabilities and prioritising mitigation efforts.
        """)
        st.markdown("""---""")
        if selected_model == "mistral-small-latest":
            st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
            
        # Create a submit button for Attack Tree
        attack_tree_submit_button = st.button(label="Generate Attack Tree")
        
        if attack_tree_submit_button and st.session_state.get('threat_model'):
            attack_tree_prompt = at_json_to_markdown(st.session_state.get('arch_explanation'), st.session_state.get('threat_model'))
            #  Show a spinner while generating the attack tree
            with st.spinner("Generating attack tree..."):
                try:
                    attack_tree = get_attack_tree(api_key, selected_model, attack_tree_prompt, system_context)
                    
                    # Save the generated code in session state
                    st.session_state['attack_tree'] = attack_tree
                    
                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")
        
        # Check if we have saved code in session state to display
        if 'attack_tree' in st.session_state:
            st.write("Attack Tree Code:")
            st.code(st.session_state['attack_tree'])
            st.write("Attack Tree Diagram Preview:")
            mermaid(st.session_state['attack_tree'])
            
            col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
            
            with col1:              
                st.download_button(
                    label="Download Diagram Code",
                    data=st.session_state['attack_tree'],
                    file_name="attack_tree.md",
                    mime="text/plain",
                    help="Download the Mermaid code for the attack tree diagram."
                )

            with col2:
                mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")

            # Empty columns for layout alignment
            with col3:
                st.write("")
            with col4:
                st.write("")
            with col5:
                st.write("")
        else:
            st.error("Please generate an architectural explanation and threat model first.")


    with tab4:
        st.markdown("""
        Automation Markup Language (AutomationML) is an XML-based standard for representing industrial automation systems. It enables the exchange of information about system components,
        their relationships, and configurations. Generating an AutomationML file helps in documenting the system architecture and security considerations in a structured format.
        """)
        st.markdown("""---""")
        if st.button("Generate AutomationML File"):
            if 'arch_explanation' in st.session_state and 'threat_model' in st.session_state and 'attack_tree' in st.session_state:
                
                prompt = create_aml_prompt(
                    st.session_state['arch_explanation'],
                    st.session_state['threat_model'],
                    st.session_state['attack_tree']
                )
                
                with st.spinner("Generating AutomationML file..."):
                    try:
                        aml_content = call_mistral(
                            api_key,
                            prompt,
                            image_bytes if 'image_bytes' in locals() else b'',
                            selected_model,
                            max_tokens=max_tokens,  # adjust as needed
                            response_as_json=False
                        )
                        st.session_state['aml_file'] = aml_content
                    except Exception as e:
                        st.error(f"Failed to generate AutomationML file: {str(e)}")
            else:
                st.error("Please generate an architectural explanation, threat model, and attack tree first.")

        if 'aml_file' in st.session_state:
            st.subheader("Generated AutomationML File")
            st.code(st.session_state['aml_file'], language='xml')
            st.download_button(
                label="Download AutomationML File",
                data=st.session_state['aml_file'],
                file_name="system_model.aml",
                mime="application/xml",
            )


    with tab5:
        st.markdown("""
    DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
    **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
    focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
    """)
        st.markdown("""---""")
        
        dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
        if dread_assessment_submit_button and st.session_state['threat_model']:
            threats_markdown = tm_json_to_markdown(st.session_state['threat_model'], [])
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown, system_context)

            with st.spinner("Generating DREAD Risk Assessment..."):
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        dread_assessment = get_dread_assessment(api_key, selected_model, dread_assessment_prompt)
                        st.session_state['dread_assessment'] = dread_assessment
                        break
                    except Exception as e:
                        if attempt == max_retries - 1:
                            st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                            dread_assessment = {"Risk Assessment": []}

            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)

            # Restore from session state if available
            if 'dread_assessment' in st.session_state:
                dread_assessment = st.session_state['dread_assessment']
                dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
            
            st.markdown("## DREAD Risk Assessment")
            st.markdown("The table below shows the DREAD risk assessment for each identified threat. The Risk Score is calculated as the average of the five DREAD categories.")
            st.markdown(dread_assessment_markdown, unsafe_allow_html=False)
            
            st.download_button(
                label="Download DREAD Risk Assessment",
                data=dread_assessment_markdown,
                file_name="dread_assessment.md",
                mime="text/markdown",
            )
        else:
            st.error("Please generate a threat model first before requesting a DREAD risk assessment.")

    with tab6:
        st.markdown("""
    Placeholder for mitigation strategies using real-time recommendations.
    """)
        st.markdown("""---""")


if __name__ == "__main__":
    main()