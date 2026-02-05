# Third-party imports
import streamlit as st
import json

# Local application imports
from utils import *


def tab_attack_tree():
    st.info("Use this tab to generate an attack tree and corresponding attack paths based on the architectural narration and threat model. You can also upload a previously saved attack tree data file in JSON format to visualise and extract attack paths.")
    st.markdown("""---""")

    with st.container():
        col1, col2 = st.columns(2)

    with col1:
        if all(key in st.session_state for key in ("arch_narration", "threat_model")):
            if st.button("Generate Attack Tree and Paths"):
                attack_tree_prompt = at_json_to_markdown(st.session_state.get('arch_narration'), st.session_state.get('threat_model'))
                with st.spinner("Generating attack tree and paths..."):
                    try:
                        st.session_state['attack_tree_data'] = gen_attack_tree(st.session_state['api_key'], attack_tree_prompt)
                        st.session_state['attack_tree'] = convert_tree_to_mermaid(st.session_state['attack_tree_data'])
                        st.session_state['attack_paths'] = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
                    except Exception as e:
                        st.error(f"Error generating attack tree: {e}")
        else:
            st.warning("Generate an architectural narration and threat model first, or upload a saved attack tree data file to proceed.")

    with col2:
        uploaded_data = st.file_uploader(
            "Upload attack tree data file (.json)", type=["json"]
        )
        if uploaded_data is not None:
            json_bytes = uploaded_data.read()  # bytes
            json_str = json_bytes.decode("utf-8")  # decode to string
            at_dict = json.loads(json_str)  # parse JSON string to dict
            st.session_state['attack_tree_data'] = at_dict
            st.success("Attack tree data uploaded successfully.")
            st.session_state['attack_tree'] = convert_tree_to_mermaid(st.session_state['attack_tree_data'])
            st.session_state['attack_paths'] = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
    
    #----------------------------------------------------------------------------------------------
    # Display Attack Tree and Paths
    #----------------------------------------------------------------------------------------------
    if 'attack_tree' in st.session_state:
        st.write("Attack Paths:")
        st.code(st.session_state['attack_paths'])
        st.write("Attack Tree Code:")
        st.code(st.session_state['attack_tree'])
        st.write("Attack Tree Diagram Preview:")
        mermaid(st.session_state['attack_tree'])

        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button(
                label="Download Attack Tree Code (Mermaid)",
                data=st.session_state['attack_tree'],
                file_name="attack_tree.md",
                mime="text/markdown",
                help="Download the Mermaid code for the attack tree.",
                key = "download_attack_tree"
            )
        with col2:
            st.link_button("Open Mermaid Live", "https://mermaid.live")
        with col3:
            st.download_button(
                label="Download Attack Tree Data (JSON)",
                data=json.dumps(st.session_state['attack_tree_data'], indent=2),
                file_name="attack_tree.json",
                mime="json",
                help="Download the raw attack tree data.",
                key = "download_attack_tree_data"
            )