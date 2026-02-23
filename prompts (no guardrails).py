# Third-party imports
import streamlit as st

# Utility Functions for Prompt Creation

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
7. Probabilities: 0.0-1.0 floats
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