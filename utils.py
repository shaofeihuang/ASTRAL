import json, re
import streamlit as st
import streamlit.components.v1 as components
import xml.etree.ElementTree as ET
from datetime import datetime
from bayesian import *
from prompts import *
from mistralai import Mistral
from anthropic import Anthropic


def on_model_provider_change():
    """Update token limit and selected model when model provider changes"""
    new_provider = st.session_state.model_provider
    provider_key = f"{new_provider}:default"
    if provider_key in model_token_limits:
        st.session_state.token_limit = model_token_limits[provider_key]["default"]
    else:
        st.session_state.token_limit = 8000
    if 'current_model_key' in st.session_state:
        del st.session_state.current_model_key
    if new_provider == "Anthropic API":
        st.session_state.selected_model = "claude-sonnet-4"
    elif new_provider == "Mistral API":
        st.session_state.selected_model = "mistral-large-latest"


def on_model_selection_change():
    """Update token limit when specific model is selected"""
    if 'model_provider' not in st.session_state or 'selected_model' not in st.session_state:
        return  
    model_provider = st.session_state.model_provider
    selected_model = st.session_state.selected_model
    model_key = f"{model_provider}:{selected_model}"
    if model_key in model_token_limits:
        st.session_state.token_limit = model_token_limits[model_key]["default"]
    else:
        provider_key = f"{model_provider}:default"
        if provider_key in model_token_limits:
            st.session_state.token_limit = model_token_limits[provider_key]["default"]
    if 'current_model_key' in st.session_state:
        del st.session_state.current_model_key


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
        return json.loads(content)
    else:
        return content


def call_anthropic(api_key, prompt_text: str, image_bytes: bytes, model_name: str, max_tokens: int, response_as_json: bool = False):
    client = Anthropic(api_key=anthropic_api_key)
    
    # Check if we're using Claude 3.7
    is_claude_3_7 = "claude-3-7" in anthropic_model.lower()
    
    # Check if we're using extended thinking mode
    is_thinking_mode = "thinking" in anthropic_model.lower()
    
    # If using thinking mode, use the actual model name without the "thinking" suffix
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else anthropic_model
    
    try:
        # For Claude 3.7, use a more explicit prompt structure
        if is_claude_3_7:
            # Add explicit JSON formatting instructions to the prompt
            json_prompt = prompt + "\n\nIMPORTANT: Your response MUST be a valid JSON object with the exact structure shown in the example above. Do not include any explanatory text, markdown formatting, or code blocks. Return only the raw JSON object."
            
            # Configure the request based on whether thinking mode is enabled
            if is_thinking_mode:
                response = client.messages.create(
                    model=actual_model,
                    max_tokens=24000,
                    thinking={
                        "type": "enabled",
                        "budget_tokens": 16000
                    },
                    system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                    messages=[
                        {"role": "user", "content": json_prompt}
                    ],
                    timeout=600  # 10-minute timeout
                )
            else:
                response = client.messages.create(
                    model=actual_model,
                    max_tokens=4096,
                    system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                    messages=[
                        {"role": "user", "content": json_prompt}
                    ],
                    timeout=300  # 5-minute timeout
                )
        else:
            # Standard handling for other Claude models
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a helpful assistant designed to output JSON. Your response must be a valid, parseable JSON object with no additional text, markdown formatting, or explanation. Do not include ```json code blocks or any other formatting - just return the raw JSON object.",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                timeout=300  # 5-minute timeout
            )
        
        # Combine all text blocks into a single string
        if is_thinking_mode:
            # For thinking mode, we need to extract only the text content blocks
            full_content = ''.join(block.text for block in response.content if block.type == "text")
            
            # Store thinking content in session state for debugging/transparency (optional)
            thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
            if thinking_content:
                st.session_state['last_thinking_content'] = thinking_content
        else:
            # Standard handling for regular responses
            full_content = ''.join(block.text for block in response.content)
        
        # Parse the JSON response
        try:
            # Check for and fix common JSON formatting issues
            if is_claude_3_7:
                # Sometimes Claude 3.7 adds trailing commas which are invalid in JSON
                full_content = full_content.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
                
                # Sometimes it adds comments which are invalid in JSON
                full_content = re.sub(r'//.*?\n', '\n', full_content)
            
            response_content = json.loads(full_content)
            return response_content
        except json.JSONDecodeError as e:
            # Create a fallback response
            fallback_response = {
                "threat_model": [
                    {
                        "Threat Type": "Error",
                        "Scenario": "Failed to parse Claude response",
                        "Potential Impact": "Unable to generate threat model"
                    }
                ],
                "improvement_suggestions": [
                    "Try again - sometimes the model returns a properly formatted response on subsequent attempts",
                    "Check the logs for detailed error information"
                ]
            }
            return fallback_response
            
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        
        # Create a fallback response for timeout or other errors
        fallback_response = {
            "threat_model": [
                {
                    "Threat Type": "Error",
                    "Scenario": f"API Error: {error_message}",
                    "Potential Impact": "Unable to generate threat model"
                }
            ],
            "improvement_suggestions": [
                "For complex applications, try simplifying the input or breaking it into smaller components",
                "If you're using extended thinking mode and encountering timeouts, try the standard model instead",
                "Consider reducing the complexity of the application description"
            ]
        }
        return fallback_response
    

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

    cpd_prob, cpd_impact = compute_risk_scores(inference_exposure, inference_impact, st.session_state['aml_data'].total_elements, start_node, last_node)

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