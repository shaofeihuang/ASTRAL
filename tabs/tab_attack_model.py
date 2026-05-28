# Standard library imports
import re

# Third-party imports
import streamlit as st
import streamlit.components.v1 as components
import json

# Local application imports
from llm_functions import init_client
from prompts import create_attack_tree_prompt

# Generate attack tree using selected model provider
def generate_attack_tree(prompt):
    system_prompt = create_attack_tree_prompt()
    response = None

    def clean_json_response(response):
        if hasattr(response, 'content'):
            if isinstance(response.content, str):
                response_text = response.content
            elif isinstance(response.content, list):
                for item in response.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        response_text = item.get("text", "")
                        break
        else:
            response_text = response
        json_pattern = r'```json\s*(.*?)\s*```'
        match = re.search(json_pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip()

        code_pattern = r'```\s*(.*?)\s*```'
        match = re.search(code_pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip()

        return response_text.strip()

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

    try:
            client = init_client()
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
            response = client.invoke(messages)
    except Exception as e:
        st.error(f"Failed to generate attack tree: {str(e)}")

    try:
        return json.loads(clean_json_response(response))
    except json.JSONDecodeError:
        return extract_mermaid_code(response.content) # Fallback: try to extract Mermaid code if JSON parsing fails
    

def tab_attack_model():
    def json_to_markdown(arch_narration, threat_model):
        markdown_output = "## Architecture narration\n\n"
        markdown_output += arch_narration + "\n\n"
        markdown_output += "## Threat Model\n\n"
        markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
        markdown_output += "|-------------|----------|------------------|\n"

        for threat in threat_model:
            markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"

        return markdown_output
    
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

    st.info("Use this tab to generate an attack tree and corresponding attack paths based on the architectural narration and threat model. You can also upload a previously saved attack model data file in JSON format to visualise and extract attack paths.")
    st.markdown("""---""")

    with st.container():
        col1, col2 = st.columns(2)

    with col1:
        if all(key in st.session_state for key in ("arch_narration", "threat_model")):
            if st.button("Generate Attack Model"):
                attack_tree_prompt = json_to_markdown(st.session_state.get('arch_narration'), st.session_state.get('threat_model'))
                with st.spinner("Generating attack model..."):
                    try:
                        st.session_state['attack_tree_data'] = generate_attack_tree(attack_tree_prompt)
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