import json, re
import streamlit as st
import streamlit.components.v1 as components
import xml.etree.ElementTree as ET
from datetime import datetime
from bayesian import *
from prompts import *
from mistralai import Mistral
from anthropic import Anthropic
from openai import OpenAI


def clean_aml_content(aml_content):
    aml_content = aml_content.strip()
    if aml_content.startswith("```xml"):
        aml_content = aml_content[len("```xml"):].strip()
    if aml_content.endswith("```"):
        aml_content = aml_content[:-len("```")].strip()
    return aml_content


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


def attack_tree_to_attack_paths(tree_data):
    attack_path_lines = []

    def process_node(node, path_labels):
        # Add current node label only (omit node ID)
        path_labels = path_labels + [node["label"]]

        # If leaf node, add reversed attack path (from attacker to goal)
        if not node.get("children"):
            reversed_labels = list(reversed(path_labels))
            attack_path_lines.append(" --> ".join(reversed_labels))
        else:
            for child in node["children"]:
                process_node(child, path_labels)

    for root_node in tree_data["nodes"]:
        process_node(root_node, [])

    return "\n".join(attack_path_lines)


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
        return tree_data
    except json.JSONDecodeError:
        return extract_mermaid_code(response.choices[0].message.content) # Fallback: try to extract Mermaid code if JSON parsing fails


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


def load_model_attributes():
    aml_content = clean_aml_content(st.session_state['aml_file'])
    env = Environment(*setup_environment(aml_content))
    aml_data = AMLData(*process_AML_file(env.element_tree_root, env.t))
    st.session_state['aml_data'] = aml_data
    st.session_state['env'] = env
    st.session_state['aml_attributes'] = {
        'assets': aml_data.AssetinSystem,
        'vulnerabilities': aml_data.VulnerabilityinSystem,
        'hazards': aml_data.HazardinSystem
    }


def compute_bayesian_probabilities():
    #check_probability_data(aml_data)
    bbn_exposure, last_node = create_bbn_exposure()
    bbn_impact = create_bbn_impact(bbn_exposure)
    #check_bbn_models(bbn_exposure, bbn_impact)

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    start_node = st.session_state['start_node']

    if 'attack_paths' in st.session_state:
        start_node = st.session_state['attack_paths'].split(" --> ")[0]
        #last_node = st.session_state['attack_paths'].split(" --> ")[-1]

    #print ("[*] Start Node:", start_node, "\n[*] Last Node: ",last_node)

    cpd_prob, cpd_impact = compute_bayesian_probabilities(inference_exposure, inference_impact, st.session_state['aml_data'].total_elements, start_node, last_node)

    risk_score = cpd_prob * cpd_impact * 100

    st.session_state['cpd_prob'] = cpd_prob
    st.session_state['cpd_impact'] = cpd_impact
    st.session_state['risk_score'] = risk_score

    print('--------------------------')
    print(datetime.now())
    print('--------------------------')
    print('[+] P(Exposure): {:.4f}%'.format(cpd_prob))
    print('[+] P(Severe Impact): {:.4f}%'.format(cpd_impact))
    print('[+] Risk score: {:.2f}%'.format(risk_score))


def display_metrics():
    st.sidebar.metric("Probability of Exposure", value=f"{st.session_state.get('cpd_prob', 0):.4f}")
    st.sidebar.metric("Probability of Severe Impact", value=f"{st.session_state.get('cpd_impact', 0):.4f}")
    st.sidebar.metric("Risk Score", value=f"{st.session_state.get('risk_score', 0):.2f}%")