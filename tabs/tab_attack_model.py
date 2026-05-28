# Standard library imports
import re

# Third-party imports
import streamlit as st
import streamlit.components.v1 as components
from langchain_mistralai import ChatMistralAI
from langchain_google_genai import ChatGoogleGenerativeAI
import json

# Local application imports
from prompts import create_attack_tree_prompt
from utils import clean_response

# Create JSON schema for attack tree
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


# Convert attack tree JSON to attack paths
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


# Clean JSON response from code block markers
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


# Convert attack tree JSON to Markdown
def at_json_to_markdown(arch_narration, threat_model):
    markdown_output = "## Architecture narration\n\n"

    markdown_output += arch_narration + "\n\n"

    markdown_output += "## Threat Model\n\n"

    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"

    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"

    return markdown_output


# Convert attack tree JSON to Mermaid syntax
def convert_tree_to_mermaid(tree_data):
    mermaid_lines = ["graph BT"]
    defined_nodes = set()

    def normalize_node(node):
        if node["label"].strip() == "[U01] Attacker":
            return "attacker", node["label"]
        return node["id"], node["label"]

    def process_node(node, parent_id=None):
        node_id, node_label = normalize_node(node)

        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'

        if node_id not in defined_nodes:
            mermaid_lines.append(f'    {node_id}[{node_label}]')
            defined_nodes.add(node_id)

        if parent_id:
            mermaid_lines.append(f'    {node_id} --> {parent_id}')

        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)

    for root_node in tree_data["nodes"]:
        process_node(root_node)

    return "\n".join(mermaid_lines)


# Extract Mermaid code from text
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


# Clean Mermaid syntax to ensure proper formatting
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


# Render Mermaid diagram in Streamlit
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


# Parse attack model data from uploaded Markdown file
def parse_attack_model_markdown(md_text: str) -> dict:
    match = re.search(r"```json\s*(.*?)\s*```", md_text, re.DOTALL)
    if not match:
        raise ValueError("No JSON code block found in markdown file.")
    return json.loads(match.group(1))


# Generate attack tree using selected model provider
def generate_attack_tree(api_key, prompt):
    system_prompt = create_attack_tree_prompt()
    response = None
    try:
            if st.session_state['model_provider'] == "Mistral API":
                client = ChatMistralAI(
                    api_key=api_key,
                    model=st.session_state['selected_model']
                )
            elif st.session_state['model_provider'] == "Gemini API":
                client = ChatGoogleGenerativeAI(
                    api_key=api_key,
                    model=st.session_state['selected_model']
                )
            elif st.session_state['model_provider'] == "OpenAI API":
                # add OpenAI call here if needed
                pass
            elif st.session_state['model_provider'] == "Anthropic API":
                # add Anthropic call here if needed
                pass

            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            response = client.invoke(messages)

    except Exception as e:
        st.error(f"Failed to generate attack tree: {str(e)}")

    try:
        cleaned_response = clean_json_response(clean_response(response))
        tree_data = json.loads(cleaned_response)
        return tree_data
    except json.JSONDecodeError:
        return extract_mermaid_code(response.content) # Fallback: try to extract Mermaid code if JSON parsing fails
    

def tab_attack_model():
    st.info("Use this tab to generate an attack tree and corresponding attack paths based on the architectural narration and threat model. You can also upload a previously saved attack model data file in JSON format to visualise and extract attack paths.")
    st.markdown("""---""")

    with st.container():
        col1, col2 = st.columns(2)

    with col1:
        if all(key in st.session_state for key in ("arch_narration", "threat_model")):
            if st.button("Generate Attack Model"):
                attack_tree_prompt = at_json_to_markdown(st.session_state.get('arch_narration'), st.session_state.get('threat_model'))
                with st.spinner("Generating attack model..."):
                    try:
                        st.session_state['attack_tree_data'] = generate_attack_tree(st.session_state['api_key'], attack_tree_prompt)
                        st.session_state['attack_tree'] = convert_tree_to_mermaid(st.session_state['attack_tree_data'])
                        st.session_state['attack_paths'] = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
                    except Exception as e:
                        st.error(f"Error generating attack model: {e}")
        else:
            st.warning("Generate an architectural narration and threat model first, or upload a saved attack model data file to proceed.")

    with col2:
        uploaded_data = st.file_uploader(
            "Upload attack model data file (.json)", type=["json"]
        )
        if uploaded_data is not None:
            file_bytes = uploaded_data.read()
            file_str = file_bytes.decode("utf-8")
            at_dict = json.loads(file_str)

            st.session_state["attack_tree_data"] = at_dict
            st.session_state["attack_tree"] = convert_tree_to_mermaid(at_dict)
            st.session_state["attack_paths"] = attack_tree_to_attack_paths(at_dict)
            st.success("Attack model data uploaded successfully.")
    
    #----------------------------------------------------------------------------------------------
    # Display Attack Tree and Paths
    #----------------------------------------------------------------------------------------------
    if 'attack_tree' in st.session_state:
        st.markdown("""---""")

        st.write("Attack Paths:")
        st.code(st.session_state['attack_paths'])
        st.write("Attack Tree Code:")
        st.code(st.session_state['attack_tree'])
        st.write("Attack Tree Diagram Preview:")
        mermaid(st.session_state['attack_tree'])

        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button(
                label="Download Attack Tree (JSON)",
                data=json.dumps(st.session_state['attack_tree_data'], indent=2),
                file_name="attack_tree.json",
                mime="json",
                help="Download the raw attack tree data.",
                key = "download_attack_tree_data"
            )
        with col2:
            st.download_button(
                label="Download Attack Tree (Mermaid code)",
                data=st.session_state['attack_tree'],
                file_name="attack_tree.md",
                mime="text/markdown",
                help="Download the Mermaid code for the attack tree.",
                key = "download_attack_tree"
            )
        with col3:
            st.link_button("Open Mermaid Live", "https://mermaid.live")