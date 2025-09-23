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
        "Cyber-physical System Context",
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
def create_dread_assessment_prompt(threats):
    prompt = f"""
Act as a cyber security expert with more than 20 years of experience in threat modeling using STRIDE and DREAD methodologies.
Your task is to produce a DREAD risk assessment for the threats identified in a threat model.
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












def main():
    api_key = get_api_key()
    selected_model = get_model_choice()
    max_tokens = model_token_limits[selected_model]["default"]
    system_context = get_system_context()

    tab1, tab2, tab3, tab4 = st.tabs(["Threat Model", "Attack Tree", "DREAD", "Mitigation"])

    with tab1:
        st.markdown("""
    A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
    understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE methodology.
    """)

        st.title("DFD-based Threat Modelling with Mistral AI")

        st.markdown("""---""")

        if not api_key:
            st.sidebar.warning("Please enter your Mistral API key.")
            st.stop()

        uploaded_file = st.file_uploader(
            "Upload Architecture / Data Flow Diagram (DFD) Image", type=["png", "jpg", "jpeg", "bmp", "gif"]
        )

        if uploaded_file is not None:
            image_bytes = uploaded_file.read()
            st.image(image_bytes, caption="Uploaded DFD Image", width="stretch")

            explanation_prompt = f'''
    You are a Senior Solution Architect tasked with explaining the following data flow diagram to a Security Architect to support the threat modelling of the system. In order to complete this task you must:
        1. Analyse the diagram, particularly identifying if an "Attacker" (whether internal or external) exists and treat it as the starting point for any attack path.
        2. Explain the system architecture to the Security Architect. Your explanation should cover the key components, trust boundaries, their interactions, and any technologies used.
        3. The specific system context is: {system_context}

    Provide a direct explanation of the diagram in a clear, structured text formatted format, suitable for a professional discussion.

    IMPORTANT INSTRUCTIONS:
        - Do not start or end with any commentary.
        - Do not include any words before or after the explanation itself.
        - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be directly determined from the diagram itself.
    '''

            threat_model_prompt = f'''
    Act as a cyber security expert with more than 20 years experience of using the STRIDE-LM threat modelling methodology to produce comprehensive threat models for a wide range of applications. Your task is to analyze the provided DFD to produce a list of specific threats for the application.

    If the DFD includes an "Attacker" or an "Operator" or an "User" entity, whether internal or external, treat it as the starting point for any attack path and list threats accordingly.

    The system context is: {system_context}

    For each of the STRIDE-LM (Spoofing, Tampering, Information Disclosure, Denial of Service, Elevation of Privilege, and Lateral Movement) categories, list multiple (3 or 4) credible threats if applicable. Each threat scenario should provide a credible scenario in which the threat could occur in the context of the application. Your responses must reflect the details provided.

    Your analysis should include threats specific to cyber-physical systems and not be limited to IT-centric threats.

    When providing the threat model, use a JSON formatted response with keys "threat_model" and "improvement_suggestions". Under "threat_model", include an array of objects with keys "Threat Type", "Scenario", and "Potential Impact". Under "improvement_suggestions", list specific lacking information or gaps that would help create a more precise threat analysis (e.g., architectural details, authentication flows, data flow descriptions, technical stack, system boundaries, sensitive data handling).

    Do NOT start or end with any non-JSON text or commentary.

    Do not provide general security recommendations.
    '''

            if st.button("Generate Architectural Explanation"):
                with st.spinner("Generating architectural explanation..."):
                    try:
                        model_output = call_mistral(
                            api_key, explanation_prompt, image_bytes, selected_model, max_tokens, response_as_json=False
                        )
                        st.subheader("Architectural Explanation")
                        st.session_state['arch_explanation'] = model_output
                        st.write(model_output)
                        st.download_button(
                            label="Download Architectural Explanation",
                            data=model_output,
                            file_name="arch_explanation.md",
                            mime="text/markdown",
                        )
                    except Exception as e:
                        st.error(f"Failed to generate architectural explanation: {str(e)}")

            if st.button("Generate STRIDE-LM Threat Model"):
                with st.spinner("Generating STRIDE-LM threat model..."):
                    try:
                        model_output = call_mistral(
                            api_key, threat_model_prompt, image_bytes, selected_model, max_tokens, response_as_json=True
                        )
                        st.subheader("Generated STRIDE-LM Threat Model")
                        threat_model = model_output.get("threat_model", [])
                        improvement_suggestions = model_output.get("improvement_suggestions", [])
                        st.session_state['threat_model'] = threat_model
                        markdown_output = tm_json_to_markdown(threat_model, improvement_suggestions)
                        st.markdown(markdown_output)
                        st.download_button(
                            label="Download Threat Model",
                            data=markdown_output,
                            file_name="threat_model.md",
                            mime="text/markdown",
                        )
                    except Exception as e:
                        st.error(f"Failed to generate threat model: {str(e)}")

    with tab2:
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
                    st.write("Attack Tree Code:")
                    st.code(mermaid_code)
                    st.write("Attack Tree Diagram Preview:")
                    mermaid(mermaid_code)
                    
                    col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
                    
                    with col1:              
                        st.download_button(
                            label="Download Diagram Code",
                            data=mermaid_code,
                            file_name="attack_tree.md",
                            mime="text/plain",
                            help="Download the Mermaid code for the attack tree diagram."
                        )

                    with col2:
                        mermaid_live_button = st.link_button("Open Mermaid Live", "https://mermaid.live")
                    
                    with col3:
                        st.write("")
                    
                    with col4:
                        st.write("")
                    
                    with col5:
                        st.write("")
                    
                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")
        else:
            st.error("Please generate an architectural explanation and threat model first before generating an attack tree.")

    with tab3:
        st.markdown("""
    DREAD is a method for evaluating and prioritising risks associated with security threats. It assesses threats based on **D**amage potential, 
    **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. This helps in determining the overall risk level and 
    focusing on the most critical threats first. Use this tab to perform a DREAD risk assessment for your application / system.
    """)
        st.markdown("""---""")
        
        dread_assessment_submit_button = st.button(label="Generate DREAD Risk Assessment")
        if dread_assessment_submit_button and st.session_state['threat_model']:
            threats_markdown = tm_json_to_markdown(st.session_state['threat_model'], [])
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown)

            with st.spinner("Generating DREAD Risk Assessment..."):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    dread_assessment = get_dread_assessment(api_key, selected_model, dread_assessment_prompt)
                        
                    st.session_state['dread_assessment'] = dread_assessment
                    break  # Exit the loop if successful
                retry_count += 1
                if retry_count == max_retries:
                    st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                    dread_assessment = {"Risk Assessment": []}
                    # Add debug information
                    st.error("Debug: No threats were found in the response. Please try generating the threat model again.")
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
            
            # Add debug information about the assessment
            if not dread_assessment.get("Risk Assessment"):
                st.warning("Debug: The DREAD assessment response is empty. Please ensure you have generated a threat model first.")
            
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

    with tab4:
        st.markdown("""
    Placeholder for mitigation strategies using real-time recommendations.
    """)
        st.markdown("""---""")


if __name__ == "__main__":
    main()
