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


# Function to create a prompt to generate mitigating controls
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


def clean_json_response(response_text):
    # Remove markdown JSON code block if present
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # If no JSON code block, try to find content between any code blocks
    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    
    # If no code blocks, return the original text stripped
    return response_text.strip()


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
        # Convert the JSON string in the 'content' field to a Python dictionary
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        dread_assessment = {}

    return dread_assessment


def convert_tree_to_mermaid(tree_data):
    mermaid_lines = ["graph TD"]
    
    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]
        
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'
        
        mermaid_lines.append(f'    {node_id}[{node_label}]')
        
        if parent_id:
            mermaid_lines.append(f'    {parent_id} --> {node_id}')
        
        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)
    
    for root_node in tree_data["nodes"]:
        process_node(root_node)
    
    return "\n".join(mermaid_lines)

def create_json_structure_prompt():
    return """Your task is to analyze the threat model and create an attack tree structure in JSON format. If an attacker entity is present, use it as the starting point for the attack paths. Each node in the tree should represent a specific attack vector or goal, with child nodes representing sub-goals or methods to achieve the parent goal.

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
                            "label": "Exploit OAuth2 Vulnerabilities"
                        }
                    ]
                }
            ]
        }
    ]
}

Rules:
- Use simple IDs (root, auth, auth1, data, etc.)
- Make labels clear and descriptive
- Include all attack paths and sub-paths
- Maintain proper parent-child relationships
- Ensure the JSON is properly formatted

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT."""


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


def get_attack_tree(api_key, selected_model, prompt):
    client = Mistral(api_key=api_key)
    system_prompt = create_json_structure_prompt()
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
    
    # Fix missing brackets around node labels
    def fix_node_brackets(match):
        node_id = match.group(1)
        if not any(c in node_id for c in '[](){}'):
            return f'{node_id}[{node_id}]'
        return node_id
    code = re.sub(r'(?:^|\s)(\w+)(?:\s|$)', fix_node_brackets, code)
    
    # Ensure node IDs with spaces are properly quoted
    def quote_node_labels(match):
        label = match.group(1)
        if ' ' in label and not label.startswith('"'):
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', quote_node_labels, code)
    
    # Fix parentheses in node labels
    def fix_parentheses(match):
        label = match.group(1)
        if '(' in label or ')' in label:
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', fix_parentheses, code)
    
    # Ensure proper line endings
    code = code.replace('\r\n', '\n').strip()
    
    return code


# Function to render Mermaid diagram
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

def load_text_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    except Exception as e:
        st.error(f"Failed to load file {filepath}: {str(e)}")
        return ""
    

def create_automationml_prompt_from_files(arch_explanation, threat_model, custom_spec_text, example_aml_content):
    threat_model_md = tm_json_to_markdown(threat_model, [])
    return f"""
You are an expert in AutomationML (AML) file generation according to the IEC 62714 standard.

Generate a complete AutomationML (AML) XML file content that represents the system architecture, components, and security considerations 
based on the inputs below.

Please strictly follow these custom specifications and formatting guidelines which differ from the standard AutomationML:

{custom_spec_text}

Use the following example AutomationML file as a reference for structure, conventions, and common patterns:

{example_aml_content}

Inputs:

Architecture Explanation:
{arch_explanation}

Threat Model (in markdown table):
{threat_model_md}

Output requirements:
- The output must be a valid AutomationML XML file content, starting with the XML declaration <?xml version="1.0" encoding="UTF-8"?>.
- Maintain proper XML indentation and well-formed structure.
- Include all relevant components and threat considerations as per the custom spec and example.
- Do NOT include any explanations or extra text, only the AutomationML XML content.

Generate the AutomationML file now.
"""









def main():
    api_key = get_api_key()
    selected_model = get_model_choice()
    max_tokens = model_token_limits[selected_model]["default"]
    system_context = get_system_context()

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Architecture", "Threat Model", "AutomationML", "Attack Tree", "DREAD", "Mitigation"])

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

            explanation_prompt = f'''
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
        # Generate Architectural Explanation Button
        if st.button("Generate Architectural Explanation", key="gen_arch_exp"):
            with st.spinner("Generating architectural explanation..."):
                try:
                    model_output = call_mistral(
                        api_key, explanation_prompt, image_bytes, selected_model, max_tokens, response_as_json=False
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



    with tab2:
        st.markdown("""
        A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
        understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE-LM methodology.
        """)
        st.markdown("""---""")
        threat_model_prompt = f'''
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
        Automation Markup Language (AutomationML) is an XML-based standard for representing industrial automation systems. It enables the exchange of information about system components,
        their relationships, and configurations. Generating an AutomationML file helps in documenting the system architecture and security considerations in a structured format.
        """)
        st.markdown("""---""")
        if st.button("Generate AutomationML File"):
            if 'arch_explanation' in st.session_state and 'threat_model' in st.session_state:
                custom_spec_text = load_text_file("aml_spec.txt")
                example_aml_content = load_text_file("aml_example.xml")
                
                prompt = create_automationml_prompt_from_files(
                    st.session_state['arch_explanation'],
                    st.session_state['threat_model'],
                    custom_spec_text,
                    example_aml_content
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
                        st.session_state['automationml_file'] = aml_content
                    except Exception as e:
                        st.error(f"Failed to generate AutomationML file: {str(e)}")
            else:
                st.error("Please generate an architectural explanation and threat model first.")

        if 'automationml_file' in st.session_state:
            st.subheader("Generated AutomationML File")
            st.code(st.session_state['automationml_file'], language='xml')
            st.download_button(
                label="Download AutomationML File",
                data=st.session_state['automationml_file'],
                file_name="system_model.aml",
                mime="application/xml",
            )

    with tab4:
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
                    mermaid_code = get_attack_tree(api_key, selected_model, attack_tree_prompt)
                    
                    # Save the generated code in session state
                    st.session_state['mermaid_code'] = mermaid_code
                    
                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")
        
        # Check if we have saved code in session state to display
        if 'mermaid_code' in st.session_state:
            st.write("Attack Tree Code:")
            st.code(st.session_state['mermaid_code'])
            st.write("Attack Tree Diagram Preview:")
            mermaid(st.session_state['mermaid_code'])
            
            col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
            
            with col1:              
                st.download_button(
                    label="Download Diagram Code",
                    data=st.session_state['mermaid_code'],
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
            st.error("Please generate an architectural explanation and threat model first before generating an attack tree.")

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