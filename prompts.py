# Third-party imports
import streamlit as st

# Utility Functions for Prompt Creation

def create_arch_narration_prompt_text():
    prompt = f'''
You are a Senior Solution Architect tasked with narrating a system architectural text description to a Senior Security Architect experienced in IEC 62443 and the Purdue model. Your narration supports threat modelling and attack tree development for a cyber-physical system, even if the architecture appears IT-centric.

System context: {st.session_state['system_context']}

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

Think deeply to thoroughly analyse the artefact text description and provide a structured narration strictly based on the content, covering:
1. Attacker or Attack-Capable Entities (explicit or implied, e.g., adversaries, operators)
2. Key Components (systems, devices, applications, network infrastructure, sensors, actuators, OT assets)
3. Trust Boundaries and Purdue Zones
4. Data Flows and Interactions (including protocols, data types, communication links)
5. Technologies, Platforms, and Standards
6. Assets and Functions with cyber-physical significance (PLCs, controllers, field devices, routers, meters, etc.)
7. Attack Entry Points (explicit or implied entities that could initiate attacks)
8. Any other architectural details supporting threat modelling and attack tree development

Structure your response using these exact section headers only:
- Attacker or Attack-Capable Entities  
- Key Components  
- Trust Boundaries and Purdue Zones  
- Data Flows & Interactions  
- Technologies and Protocols  
- Assets and Functions  
- Attack Entry Points  

IMPORTANT - Follow these strictly enforced semantic guardrails:
- Base your narration solely on the provided diagram; do not infer or assume details beyond what is visible.
- Do not start or end with commentary or extra text.
- Do not infer or guess beyond what is visibly present.
- Do not provide recommendations—only factual narration.
- Use only the specified headers and no additional formatting.
'''
    return prompt

def create_arch_narration_prompt():
    prompt = f'''
You are a Senior Solution Architect tasked with narrating a system architectural diagram (e.g., Data Flow Diagram) to a Senior Security Architect experienced in IEC 62443 and the Purdue model. Your narration supports threat modelling and attack tree development for a cyber-physical system, even if the architecture appears IT-centric.

System context: {st.session_state['system_context']}

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

Think deeply to thoroughly analyse the diagram and provide a structured narration strictly based on visible content, covering:
1. Attacker or Attack-Capable Entities (explicit or implied, e.g., adversaries, operators)
2. Key Components (systems, devices, applications, network infrastructure, sensors, actuators, OT assets)
3. Trust Boundaries and Purdue Zones
4. Data Flows and Interactions (including protocols, data types, communication links)
5. Technologies, Platforms, and Standards
6. Assets and Functions with cyber-physical significance (PLCs, controllers, field devices, routers, meters, etc.)
7. Attack Entry Points (explicit or implied entities that could initiate attacks)
8. Any other architectural details supporting threat modelling and attack tree development

Structure your response using these exact section headers only:
- Attacker or Attack-Capable Entities  
- Key Components  
- Trust Boundaries and Purdue Zones  
- Data Flows & Interactions  
- Technologies and Protocols  
- Assets and Functions  
- Attack Entry Points  

IMPORTANT - Follow these strictly enforced semantic guardrails:
- Base your narration solely on the provided diagram; do not infer or assume details beyond what is visible.
- Do not start or end with commentary or extra text.
- Do not infer or guess beyond what is visibly present.
- Do not provide recommendations—only factual narration.
- Use only the specified headers and no additional formatting.
'''
    return prompt


def create_threat_model_prompt():
    prompt = f'''
You are a senior cyber security expert with over 20 years of experience in cyber-physical systems (CPS) risk and threat modelling, including deep expertise in STRIDE-LM and safety/security co-analysis. You have applied STRIDE-LM extensively in ICS, SCADA, and related CPS domains.

Your task is to think deeply to thoroughly analyse the provided system architectural diagram (e.g., Data Flow Diagram) along with any accompanying documentation to produce a comprehensive list of specific threat scenarios relevant to the application.

System context: {st.session_state['system_context']}

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

IMPORTANT - Follow these strictly enforced semantic guardrails:
1. If the diagram includes an "Attacker" entity—whether internal, external, explicit, or implicit—treat it as the origin for possible attack paths and enumerate realistic threats accordingly.
2. For each STRIDE-LM category, identify 3 to 4 credible threat scenarios if applicable. Each scenario must describe a concrete, context-specific attack, avoiding generic descriptions.
3. Focus your analysis on cyber-physical systems. Address system-level impacts such as disruption of physical processes, loss of control, cascading failures, or safety hazards rather than purely IT-centric threats.
4. Consider multiple potential attacker objectives (e.g., power disruption, asset damage, persistent foothold in isolated OT environments, bypassing safety controls).
5. Leverage and extract from the accompanying documentation to reflect the assets, vulnerabilities (both CVE-linked and non-CVE-linked), hazards, and objectives in each scenario.
6. Identify and list only CVEs that are visible in the accompanying documentation. For each CVE, provide the CVE identifier, the affected product, and a brief description. Indicate if the CVE has been observed in known attack campaigns (e.g., BlackEnergy, FrostyGoop), with references.
7. Apply FMECA-style reasoning where applicable to identify failure modes, their effects, and potential cascading consequences.
8. Format your response strictly as JSON with these top-level keys:
   - `"threat_model"`: an array of threat scenario objects.
   - `"arch_suggestions"`: a list of missing architectural information (e.g., authentication flows, protocol details, safety system integration, segmentation) needed for more precise modelling.
9. Each threat scenario object must contain the following keys:
   - `"Threat Type"`, based on STRIDE-LM categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege, Lateral Movement).
   - `"Scenario"`: a detailed narration integrating information about assets, vulnerabilities (including CVE and non-CVE), hazards, and attacker objectives. Include references to any CVEs mentioned, and highlight if they were employed in known attack campaigns.
   - `"Potential Impact"`
10. Do NOT include general security recommendations or any commentary.
11. Provide no text outside the JSON structure.
'''
    return prompt


def create_attack_tree_prompt():
    prompt = """
You are a senior cyber security expert with over 20 years of experience in cyber-physical system (CPS) threat management and incident response.

Your task is to think deeply to thoroughly analyse the threat model and create an attack tree structure in JSON format.

System context: {st.session_state['system_context']}

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

IMPORTANT - Follow these strictly enforced semantic guardrails:
1. The one and only root node represents the goal node [G01] CPS Disruption, which is the disruption or stoppage of cyber-physical system operations, taking into account the specific context of the system being analysed.
2. The one and only terminal node represents the attacker node [U01] Attacker, which is at the bottom of the tree structure and connected to all the attack paths leading to the attack goal.
- The attacker node should be labeled with the prefix `[U01] Attacker`.
- This attacker node must have children links (edges) to all leaf nodes (the last nodes) in every attack path in the tree.
- This represents the attacker as the origin of all end-stage threats in the attack tree.
3. Each node in the tree should represent an Asset, Vulnerability, Hazard, or Goal.
4. Each node must be unique and not reused across different branches of the tree. If a node appears in multiple attack paths, it should be duplicated with a unique ID to maintain the tree structure.
5. The tree should include all relevant attack paths and sub-paths based on the threat model.
6. Analyse if assets, hazards, or vulnerabilities may be linked to assets, hazards, or vulnerabilities in separate attack paths, and if so, represent these relationships appropriately in the tree structure.
7. Each node label must begin with a prefix (alphabet followed by two numbers) indicating its type:
- `[A##]` for Asset nodes
- `[V##]` for Vulnerability nodes
- `[H##]` for Hazard nodes
- `[G01]` for Goal node
- `[U01]` for Attacker node
8. Maintain parent-child relationships strictly according to the rules as follows:
- Asset nodes may have children that are Vulnerabilities, Hazards, or other Assets.
- Goal node may have children that are Asset, Vulnerability or Hazard nodes.
- Vulnerability nodes may have children that are Vulnerabilities or Assets, but never Hazards.
- Hazard nodes may have children that are Hazards or Assets, but never Vulnerabilities.
9. Use simple IDs (e.g., root, vul1, haz1, asset1).
10. Make labels clear, descriptive, and correctly prefixed.
11. Ensure the JSON is properly formatted. The JSON structure should follow this format:
{
    "nodes": [
        {
            "id": "root",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "auth",
                    "label": "Gain Unauthorised Access",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "Exploit OAuth2 Vulnerabilities",
                            "children": [
                                {
                                    "id": "attacker",
                                    "label": "[U01] Attacker"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    ]
}

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT.
"""
    return prompt


def create_aml_prompt_step_1(arch_narration, threat_model, attack_paths):
    """
    Step 1: Generate InternalElement XML blocks from architecture, threats, and attack paths.
    Outputs properly structured AML InternalElements with correct attributes and interfaces.
    """
    prompt = f"""You are an expert AutomationML (IEC 62714) generator for cyber-physical systems threat modelling.

TASK: Generate ONLY <InternalElement> XML blocks for ALL nodes appearing in the attack paths.
Use EXACT node labels from the inputs. Do NOT invent nodes.

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

## NODE CLASSIFICATION & TEMPLATES

### 1. ASSETS [A##] - Software/Hardware
RefBaseSystemUnitPath: 
- Software: "AssetOfICS/Software/Application" 
- Hardware: "AssetOfICS/Hardware/Machine"

TEMPLATE:
<InternalElement Name="[A01] PLC Controller" ID="[A01] PLC Controller" RefBaseSystemUnitPath="AssetOfICS/Hardware/Machine">
  <Attribute Name="AutomationEquipments" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/AutomationEquipments">
    <Attribute Name="Vendor" AttributeDataType="xs:string"><Value>Schneider</Value></Attribute>
    <Attribute Name="Version" AttributeDataType="xs:string"><Value>3.2.1</Value></Attribute>
    <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float"><Value>0.0005</Value></Attribute>
    <Attribute Name="Impact Rating" AttributeDataType="xs:float"><Value>0.85</Value></Attribute>
    <Attribute Name="Date of first use" AttributeDataType="xs:string"><Value>2024-06-15</Value></Attribute>
  </Attribute>
  <ExternalInterface Name="Interface_A01" ID="Interface_A01" RefBaseClassPath="ConnectionBetnAssets/Network"/>
</InternalElement>

### 2. VULNERABILITIES [V##]
RefBaseSystemUnitPath: "VulnerabilityforSystem/Vulnerability"

TEMPLATE:
<InternalElement Name="[V01] Weak Authentication" ID="[V01] Weak Authentication" RefBaseSystemUnitPath="VulnerabilityforSystem/Vulnerability">
  <Attribute Name="Vulnerability" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Vulnerability">
    <Attribute Name="CVE" AttributeDataType="xs:string"><Value>N/A</Value></Attribute>
    <Attribute Name="CVSS" AttributeDataType="xs:string"><Value>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N</Value></Attribute>
    <Attribute Name="EPSS" AttributeDataType="xs:string"><Value>N/A</Value></Attribute>
    <Attribute Name="Attack Name" AttributeDataType="xs:string"><Value>Brute Force Attack</Value></Attribute>
    <Attribute Name="Probability of Impact" AttributeDataType="xs:string"><Value>0.8</Value></Attribute>
    <Attribute Name="Probability of Exposure" AttributeDataType="xs:string"><Value>0.65</Value></Attribute>
    <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string"><Value>0.4</Value></Attribute>
  </Attribute>
  <ExternalInterface Name="Interface_V01" ID="Interface_V01" RefBaseClassPath="ConnectionBetnAssets/Network"/>
</InternalElement>

### 3. HAZARDS [H##]
RefBaseSystemUnitPath: "HazardforSystem/Hazard"

TEMPLATE:
<InternalElement Name="[H01] Motor Overheat" ID="[H01] Motor Overheat" RefBaseSystemUnitPath="HazardforSystem/Hazard">
  <Attribute Name="Hazard" AttributeDataType="xs:string" RefAttributeType="AttributeTypeLib/Hazard">
    <Attribute Name="Impact Rating" AttributeDataType="xs:float"><Value>0.9</Value></Attribute>
    <Attribute Name="Consequence" AttributeDataType="xs:string"><Value>Equipment Damage</Value></Attribute>
    <Attribute Name="Causes" AttributeDataType="xs:string"><Value>Command Injection</Value></Attribute>
  </Attribute>
  <ExternalInterface Name="Interface_H01" ID="Interface_H01" RefBaseClassPath="ConnectionBetnAssets/Network"/>
</InternalElement>

### 4. ATTACKERS [U01]
RefBaseSystemUnitPath: "AssetOfICS/User"

TEMPLATE:
<InternalElement Name="[U01] Attacker" ID="[U01] Attacker" RefBaseSystemUnitPath="AssetOfICS/User">
  <Attribute Name="HumanErrorEstimationPercentage" AttributeDataType="xs:string"><Value>0.05</Value></Attribute>
  <ExternalInterface Name="Interface_U01" ID="Interface_U01" RefBaseClassPath="ConnectionBetnAssets/User"/>
</InternalElement>

### 5. GOALS [G##] 
RefBaseSystemUnitPath: "AssetOfICS/Software/Application"

## INPUT DATA

Architecture Narration:
{arch_narration}

Threat Model:
{threat_model}

Attack Paths (extract ALL unique nodes):
{attack_paths}

## IMPORTANT - Follow these strictly enforced semantic guardrails:
1. Use EXACT node names from attack paths (preserve [A##], [V##] prefixes)
2. Classify each node type correctly from context
3. EVERY InternalElement MUST have exactly 1 ExternalInterface
4. Interface ID format: "Interface_[NodePrefixOnly]" (e.g., Interface_A01, Interface_V01)
5. Populate attributes with realistic values based on node description
6. For unknown CVEs: CVE="N/A", EPSS="N/A"
7. Probabilities and failure rates: 0.0-1.0 floats
8. CVSS: Use valid vector format (CVSS:3.1/AV:N/AC:L/...)

## OUTPUT
ONLY complete <InternalElement> XML blocks, properly nested and formatted.
NO explanations, NO additional text, NO <CAEXFile> wrapper.
"""
    return prompt


def create_aml_prompt_step_2(attack_paths):
    """
    Step 2: Extract directed edges from attack paths as valid InternalLink pairs.
    Outputs JSON array of [source_node_id, target_node_id] pairs.
    """
    prompt = f"""You are an expert at extracting directed edges from attack path sequences for AutomationML InternalLinks.

TASK: Parse the attack paths and output ONLY a JSON array of valid [source_node_id, target_node_id] pairs.
Preserve direction exactly as shown in paths. Cover ALL attack paths completely.

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

## IMPORTANT - Follow these strictly enforced semantic guardrails:
1. Extract ONLY nodes with prefixes: [A##], [V##], [H##], [U##], [G##]
2. Direction: source -> target (follows attack flow from attacker to goal)
3. Remove duplicates - output each unique pair only once
4. Use EXACT node IDs from paths (preserve prefixes and numbers)
5. Attacker [U01] is always source for initial edges
6. Goal [G01] is always target for final edges
7. Do not create self-loops - source and target cannot be the same node

EXAMPLE:
Attack Paths:
[U01] Attacker -> [A01] Web Server -> [V01] SQL Injection -> [H01] Data Leak
[A02] Database -> [V02] Weak Auth -> [G01] System Compromise

Output:
[
  ["[U01]", "[A01]"],
  ["[A01]", "[V01]"], 
  ["[V01]", "[H01]"],
  ["[A02]", "[V02]"],
  ["[V02]", "[G01]"]
]

INPUT:
Attack Paths:
{attack_paths}

OUTPUT:
ONLY valid JSON array of string pairs. No additional text.
[
  ["[U01]", "[A01]"],
  ["[A01]", "[V01]"]
]
"""
    return prompt


def create_aml_prompt_step_3(valid_pairs_json, map_str):
    """
    Step 3: Generate InternalLink XML elements from valid pairs and interface mapping.
    """
    prompt = f"""You are an AutomationML XML generator.

TASK: Generate ONLY <InternalLink> XML elements for these EXACT pairs using the interface mapping.

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

VALID PAIRS:
{valid_pairs_json}

INTERFACE MAPPING:
{map_str}

## IMPORTANT - Follow these strictly enforced semantic guardrails:

1. For each [source,target] pair:
   - RefPartnerSideA = Interface ID of SOURCE node from mapping
   - RefPartnerSideB = Interface ID of TARGET node from mapping  
   - Name = "sourceID_targetID" (e.g. "U01_A01")
2. ONLY generate links for pairs in the valid_pairs_json list
3. Use EXACT interface IDs from mapping

EXAMPLE:
Pair: ["[U01]", "[A01]"]
Mapping: 
[U01]: Interface_U01
[A01]: Interface_A01

Output:
<InternalLink RefPartnerSideA="Interface_U01" RefPartnerSideB="Interface_A01" Name="U01_A01"/>

INPUT PAIRS:
{valid_pairs_json}

MAPPING:
{map_str}

OUTPUT:
ONLY complete <InternalLink> XML elements. No explanations.
<InternalLink RefPartnerSideA="Interface_U01" RefPartnerSideB="Interface_A01" Name="U01_A01"/>
<InternalLink RefPartnerSideA="Interface_A01" RefPartnerSideB="Interface_V01" Name="A01_V01"/>
"""
    return prompt


def create_aml_prompt_step_4(internal_elements_xml, internal_links_xml):
    """
    Step 4: Assemble complete IEC 62714-compliant AutomationML XML document.
    """
    prompt = f"""You are an AutomationML expert focused on generating a correct and IEC 62714-conformant AutomationML XML document.

TASK: Assemble COMPLETE AutomationML XML using ONLY these validated components.

Controlled sampling configuration:
- temperature = {st.session_state['llm_temperature']}
- top_p = {st.session_state['llm_top_p']}

## REQUIRED LIBRARIES (include EXACTLY these):

InterfaceClassLib:
<InterfaceClassLib Name="ConnectionBetnAssets">
  <InterfaceClass Name="Network"/>
  <InterfaceClass Name="User"/>
</InterfaceClassLib>

SystemUnitClassLib Assets:
<SystemUnitClassLib Name="AssetOfICS">
  <SystemUnitClass Name="Software">
    <SystemUnitClass Name="Application"/>
  </SystemUnitClass>
  <SystemUnitClass Name="Hardware">
    <SystemUnitClass Name="Machine"/>
  </SystemUnitClass>
  <SystemUnitClass Name="User"/>
</SystemUnitClassLib>

SystemUnitClassLib Vulnerability:
<SystemUnitClassLib Name="VulnerabilityforSystem">
  <SystemUnitClass Name="Vulnerability">
    <Attribute Name="CVE" AttributeDataType="xs:string"/>
    <Attribute Name="CVSS" AttributeDataType="xs:string"/>
    <Attribute Name="EPSS" AttributeDataType="xs:string"/>
  </SystemUnitClass>
</SystemUnitClassLib>

SystemUnitClassLib Hazard:
<SystemUnitClassLib Name="HazardforSystem">
  <SystemUnitClass Name="Hazard"/>
</SystemUnitClassLib>

AttributeTypeLib:
<AttributeTypeLib Name="AttributeTypeLib">
  <AttributeType Name="AutomationEquipments" AttributeDataType="xs:string">
    <Attribute Name="Vendor" AttributeDataType="xs:string"/>
    <Attribute Name="Version" AttributeDataType="xs:string"/>
    <Attribute Name="FailureRatePerHour" AttributeDataType="xs:float"/>
    <Attribute Name="Impact Rating" AttributeDataType="xs:float"/>
    <Attribute Name="Date of first use" AttributeDataType="xs:string"/>
  </AttributeType>
  <AttributeType Name="Vulnerability" AttributeDataType="xs:string">
    <Attribute Name="CVE" AttributeDataType="xs:string"/>
    <Attribute Name="CVSS" AttributeDataType="xs:string"/>
    <Attribute Name="EPSS" AttributeDataType="xs:string"/>
    <Attribute Name="Attack Name" AttributeDataType="xs:string"/>
    <Attribute Name="Probability of Impact" AttributeDataType="xs:string"/>
    <Attribute Name="Probability of Exposure" AttributeDataType="xs:string"/>
    <Attribute Name="Probability of Mitigation" AttributeDataType="xs:string"/>
  </AttributeType>
  <AttributeType Name="Hazard" AttributeDataType="xs:string">
    <Attribute Name="Impact Rating" AttributeDataType="xs:float"/>
    <Attribute Name="Consequence" AttributeDataType="xs:string"/>
    <Attribute Name="Causes" AttributeDataType="xs:string"/>
  </AttributeType>
</AttributeTypeLib>

## VALIDATED COMPONENTS

InternalElements (use EXACTLY these):
{internal_elements_xml}

InternalLinks (nest inside source InternalElements):
{internal_links_xml}

## STRUCTURE REQUIRED:

<CAEXFile SchemaVersion="3.0" FileName="cps.aml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.dke.de/CAEX" xsi:schemaLocation="http://www.dke.de/CAEX CAEX_ClassModel_V.3.0.xsd">
  
  [ALL LIBRARIES ABOVE]
  
  <InstanceHierarchy Name="CPS_Architecture">
    <Version>1.0</Version>
    [ALL InternalElements from input]
  </InstanceHierarchy>

</CAEXFile>

## VALIDATION CHECKS (output NOTHING if any fail):
1. All attributes have <Value> populated
2. CVSS format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
3. All probabilities: 0.0-1.0 floats
4. Every InternalLink connects valid Interface IDs
5. InternalLinks nested inside source InternalElement
6. NO extra elements beyond input data

## OUTPUT:
ONLY complete, valid AutomationML XML. NO explanations. NO comments.
"""
    return prompt