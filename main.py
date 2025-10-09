import json, os, time, random
import streamlit as st
import pandas as pd
from datetime import date
from dotenv import load_dotenv
from prompts import *
from utils import *
from bayesian import *


model_token_limits = {
    # Claude models
    "Anthropic API:claude-sonnet-4-5-20250929": {"default": 64000, "max": 200000},
    "Anthropic API:claude-sonnet-4-20250514": {"default": 64000, "max": 200000},
    "Anthropic API:claude-opus-4-1-20250805": {"default": 64000, "max": 200000},
    "Anthropic API:claude-opus-4-20250514": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-7-sonnet-latest": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-5-haiku-latest": {"default": 64000, "max": 200000},

    # Mistral models
    "Mistral API:mistral-large-latest": {"default": 128000, "max": 128000},
    "Mistral API:mistral-medium-latest": {"default": 128000, "max": 128000},
    "Mistral API:mistral-small-latest": {"default": 128000, "max": 128000},
    "Mistral API:magistral-small-latest": {"default": 40000, "max": 40000},
    "Mistral API:magistral-medium-latest": {"default": 40000, "max": 40000},
    "Mistral API:ministral-8b-latest": {"default": 128000, "max": 128000},
    "Mistral API:pixtral-12b-latest": {"default": 128000, "max": 128000},
}


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


def main():
    load_dotenv()
    with st.sidebar:
        st.image("logo.png")

        model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["Anthropic API", "Mistral API"],
        key="model_provider",
        index=1,
        on_change=on_model_provider_change,
        help="Select the model provider you would like to use. This will determine the models available for selection.",
        )

        if model_provider == "Anthropic API":
            st.session_state['api_key'] = st.text_input("Anthropic API Key",
                                            value=os.getenv("ANTHROPIC_API_KEY"),
                                            type="password")
            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["claude-sonnet-4-5-20250929", "claude-sonnet-4-20250514", "claude-opus-4-1-20250805", "claude-opus-4-20250514",
                 "claude-3-7-sonnet-latest", "claude-3-5-haiku-latest"],
                key="selected_model",
                on_change=on_model_selection_change,
                help="Select the model you would like to use."
            )

        if model_provider == "Mistral API":
            st.session_state['api_key'] = st.text_input("Mistral API Key",
                                            value=os.getenv("MISTRAL_API_KEY"),
                                            type="password")
            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["mistral-large-latest", "mistral-medium-latest", "mistral-small-latest", "magistral-medium-latest",
                 "magistral-small-latest", "ministral-8b-latest", "pixtral-12b-latest"],
                key="selected_model",
                on_change=on_model_selection_change,
                help="Select the model you would like to use."
            )

        system_context = st.selectbox(
            "CPS System Context",
            ["Cyber-Physical System", "Heating System", "Tesla IVI System", "Solar PV Inverter Panel", "Railway CBTC System"],
            index=0,
            placeholder="Select or enter a custom description",
            accept_new_options=True,
        )

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Architecture", "Threat Model", "DREAD", "Attack Tree", "System Model", "Analysis", "Countermeasures"])

#----------------------------------------------------------------------------------------------
# Generate Architectural Explanation
#----------------------------------------------------------------------------------------------

    with tab1:
        st.title("LLM-Powered Real-Time Cyber-Physical System Decision Support")

        st.markdown("""---""")

        if 'api_key' not in st.session_state:
            st.sidebar.warning("Please enter your API key.")
            st.stop()

        uploaded_file = st.file_uploader(
            "Upload Architecture / Data Flow Diagram (DFD) Image", type=["png", "jpg", "jpeg", "bmp", "gif"]
        )

        if uploaded_file is not None:
            image_bytes = uploaded_file.read()
            st.image(image_bytes, caption="Uploaded Image", width="stretch")
            arch_expl_prompt = create_arch_expl_prompt(system_context)

            if st.button("Generate Architectural Explanation") and uploaded_file is not None:
                with st.spinner("Generating architectural explanation..."):
                    try:
                        if model_provider == "Mistral API":
                            model_output = call_mistral(
                                st.session_state['api_key'],
                                arch_expl_prompt,
                                image_bytes,
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                            st.session_state['arch_explanation'] = model_output
                    except Exception as e:
                        st.error(f"Failed to generate architectural explanation: {str(e)}")
        else:
            st.info("Please upload system architecture diagram.")

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
                "Additional Details (Optional)",
                value="",
                placeholder="Enter extra architectural specifics here.",
                height=150,
            )
            if st.button("Re-Generate Architectural Explanation"):
                with st.spinner("Generating architectural explanation..."):
                    try:
                        if model_provider == "Mistral API":
                            model_output = call_mistral(
                                st.session_state['api_key'],
                                arch_expl_prompt + "\n" + additional_detail.strip(),
                                image_bytes,
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                            st.session_state['arch_explanation'] = model_output
                            st.rerun()
                    except Exception as e:
                        st.error(f"Failed to generate architectural explanation: {str(e)}")

#----------------------------------------------------------------------------------------------
# Generate Threat Model
#----------------------------------------------------------------------------------------------

    with tab2:
        st.markdown("""
        A threat model helps identify and evaluate potential security threats to applications and systems. It provides a systematic approach to understanding possible vulnerabilities and attack vectors. The STRIDE-LM methodology expands upon the classic STRIDE framework by including seven categories of threats: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege, and **L**ateral **M**ovement. Using this method, you can comprehensively analyse your system to identify and prioritise security risks, enabling proactive mitigation. Use this tab to generate a threat model tailored to the CPS system using STRIDE-LM.
        """)
        st.markdown("""---""")
        threat_model_prompt = create_threat_model_prompt(system_context)

        if 'arch_explanation' in st.session_state:
            if st.button("Generate STRIDE-LM Threat Model"):
                with st.spinner("Generating STRIDE-LM threat model..."):
                    try:
                        if model_provider == "Mistral API":
                            model_output = call_mistral(
                                st.session_state['api_key'],
                                threat_model_prompt,
                                image_bytes,
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=True
                                )
                            st.session_state['threat_model'] = model_output.get("threat_model", [])
                            st.session_state['improvement_suggestions'] = model_output.get("improvement_suggestions", [])
                    except Exception as e:
                        st.error(f"Failed to generate threat model: {str(e)}")
        else:
            st.info("Generate an architectural explanation first to proceed.")

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

#----------------------------------------------------------------------------------------------
# Generate DREAD Risk Assessment
#----------------------------------------------------------------------------------------------

    with tab3:
        st.markdown("""
        DREAD is a structured methodology for evaluating and prioritising risks associated with security threats. It assesses each threat based on five criteria: **D**amage potential, **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. By scoring threats on these factors, organisations can calculate an overall risk level, which enables them to focus mitigation efforts on the most critical vulnerabilities first. This method supports consistent risk assessment, improves communication across teams, and helps allocate resources efficiently to protect systems effectively. Use this tab to perform a DREAD risk assessment for your application or system.
        """)
        st.markdown("""---""")
        
        if 'threat_model' in st.session_state:
            if st.button(label="Generate DREAD Risk Assessment"):
                threats_markdown = tm_json_to_markdown(st.session_state['threat_model'], [])
                dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown, system_context)
                with st.spinner("Generating DREAD Risk Assessment..."):
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            st.session_state['dread_assessment'] = get_dread_assessment(st.session_state['api_key'], selected_model, dread_assessment_prompt)
                            break
                        except Exception as e:
                            if attempt == max_retries - 1:
                                st.error(f"Error generating DREAD risk assessment after {max_retries} attempts: {e}")
                                
            if 'dread_assessment' in st.session_state:
                dread_assessment_markdown = dread_json_to_markdown(st.session_state['dread_assessment'])
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
            st.info("Generate a threat model first to proceed.")

#----------------------------------------------------------------------------------------------
# Generate Attack Trees and Attack Paths
#----------------------------------------------------------------------------------------------

    with tab4:
        st.markdown("""
        Attack trees provide a systematic method to analyse the security of cyber-physical systems. They depict potential attack scenarios in a hierarchical structure, with the attacker’s ultimate objective at the root and various paths to reach that objective represented as branches. By illustrating attack paths and their impact on critical assets, attack trees support prioritisation of mitigation strategies and enhance real-time decision-making for system resilience.
        """)
        st.markdown("""---""")

        with st.container():
            col1, col2 = st.columns(2)

        with col1:
            if all(key in st.session_state for key in ("arch_explanation", "threat_model")):
                if st.button("Generate Attack Tree and Paths"):
                    attack_tree_prompt = at_json_to_markdown(st.session_state.get('arch_explanation'), st.session_state.get('threat_model'))
                    with st.spinner("Generating attack tree and paths..."):
                        try:
                            attack_tree_data = get_attack_tree(st.session_state['api_key'], selected_model, attack_tree_prompt, system_context)
                            st.session_state['attack_tree_data'] = attack_tree_data
                            attack_tree = convert_tree_to_mermaid(attack_tree_data)
                            st.session_state['attack_tree'] = attack_tree
                            attack_paths = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
                            st.session_state['attack_paths'] = attack_paths
                        except Exception as e:
                            st.error(f"Error generating attack tree: {e}")
            else:
                st.info("Generate an architectural explanation and threat model first, or upload a saved attack tree data file to proceed.")

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
                attack_tree = convert_tree_to_mermaid(st.session_state['attack_tree_data'])
                st.session_state['attack_tree'] = attack_tree
                attack_paths = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
                st.session_state['attack_paths'] = attack_paths
            
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
                    label="Download Attack Tree Diagram",
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

#----------------------------------------------------------------------------------------------
# Generate System Model (AutomationML)
#----------------------------------------------------------------------------------------------

    with tab5:
        st.markdown("""
        Automation Markup Language (AutomationML) is an XML-based open standard for representing industrial automation systems. It builds upon the CAEX (Computer Aided Engineering Exchange) format defined in IEC 62424, which provides an object-oriented data model for system components and their hierarchical relationships. AutomationML facilitates semantic interoperability across diverse CPS domains by enabling standardised, meaningful exchange of data about physical and cyber components, their configurations, and interrelations. Use this tab to generate an AutomationML representation of the CPS system.
        """)
        st.markdown("""---""")

        def generate_aml_stepwise(arch_explanation, threat_model, attack_paths):
            max_retries = 3

            with st.spinner("Generating AutomationML Model (Step 1) ..."):
                for attempt in range(max_retries):
                    try:
                        print("[#] Generating AML - Step 1")
                        start_time = time.time()

                        prompt_step1 = create_aml_prompt_step_1(arch_explanation, threat_model, attack_paths)
                        if model_provider == "Mistral API":
                            response_step1 = call_mistral(
                                st.session_state['api_key'],
                                prompt_step1,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                        internal_elements_xml = response_step1

                        end_time = time.time()
                        elapsed_secs = end_time - start_time
                        st.success(f"Step 1 completed ({elapsed_secs:.2f} secs)")
                        break  # success, exit retry loop
                    except Exception as e:
                        if attempt == max_retries - 1:
                            st.error(f"Error generating model (Step 1) after {max_retries} attempts: {e}")
                        else:
                            delay = 2 ** attempt + random.uniform(0, 1)
                            st.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.1f} seconds...")
                            time.sleep(delay)

            with st.spinner("Generating AutomationML Model (Step 2) ..."):
                for attempt in range(max_retries):
                    try:
                        print("[#] Generating AML - Step 2")
                        start_time = time.time()

                        prompt_step2 = create_aml_prompt_step_2(attack_paths)
                        if model_provider == "Mistral API":
                            response_step2 = call_mistral(
                                st.session_state['api_key'],
                                prompt_step2,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                        valid_pairs_json = response_step2

                        end_time = time.time()
                        elapsed_secs = end_time - start_time
                        st.success(f"Step 2 completed ({elapsed_secs:.2f} secs)")
                        break  # success, exit retry loop
                    except Exception as e:
                        if attempt == max_retries - 1:
                            st.error(f"Error generating model (Step 2) after {max_retries} attempts: {e}")
                        else:
                            delay = 2 ** attempt + random.uniform(0, 1)
                            st.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.1f} seconds...")
                            time.sleep(delay)

            with st.spinner("Generating AutomationML Model (Step 3) ..."):
                for attempt in range(max_retries):
                    try:
                        print("[#] Generating AML - Step 3")
                        start_time = time.time()

                        node_to_interface_id_mapping = {}
                        pattern = r'ID="\[([A-Z0-9]+)\] [^"]+"[^>]*>.*?<ExternalInterface Name="[^"]+" ID="([^"]+)"'
                        matches = re.findall(pattern, internal_elements_xml, re.DOTALL)
                        for node_id, interface_id in matches:
                            node_to_interface_id_mapping[node_id] = interface_id

                        map_lines = [f'{node_id}: {iface_id}' for node_id, iface_id in node_to_interface_id_mapping.items()]
                        map_str = "\n".join(map_lines)

                        prompt_step3 = create_aml_prompt_step_3(valid_pairs_json, map_str)
                        if model_provider == "Mistral API":
                            response_step3 = call_mistral(
                                st.session_state['api_key'],
                                prompt_step3,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                        internal_links_xml = response_step3

                        end_time = time.time()
                        elapsed_secs = end_time - start_time
                        st.success(f"Step 3 completed ({elapsed_secs:.2f} secs)")
                        break  # success, stop retrying
                    except Exception as e:
                        if attempt == max_retries - 1:
                            st.error(f"Error generating model (Step 3) after {max_retries} attempts: {e}")
                        else:
                            delay = 2 ** attempt + random.uniform(0, 1)  # exponential backoff + jitter
                            st.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.1f} seconds...")
                            time.sleep(delay)

            with st.spinner("Generating AutomationML Model (Step 4) ..."):
                for attempt in range(max_retries):
                    try:
                        print("[#] Generating AML - Step 4 (Final)")
                        start_time = time.time()
                        prompt_step4 = create_aml_prompt_step_4(internal_elements_xml, internal_links_xml)
                        if model_provider == "Mistral API":
                            response_step4 = call_mistral(
                                st.session_state['api_key'],
                                prompt_step4,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                        end_time = time.time()
                        elapsed_secs = end_time - start_time
                        st.success(f"Step 4 completed ({elapsed_secs:.2f} secs)")
                        break  # success, exit retry loop
                    except Exception as e:
                        if attempt == max_retries - 1:
                            st.error(f"Error generating model (Step 4) after {max_retries} attempts: {e}")
                        else:
                            delay = 2 ** attempt + random.uniform(0, 1)  # exponential backoff with jitter
                            st.warning(f"Attempt {attempt + 1} failed, retrying in {delay:.1f} seconds...")
                            time.sleep(delay)
                
                final_aml_xml = response_step4

            return final_aml_xml

        with st.container():
            col1, col2 = st.columns(2)

        with col1:
            if all(key in st.session_state for key in ("arch_explanation", "threat_model", "attack_paths")):
                if st.button("Generate AutomationML File"):
                    try:
                        aml_content = generate_aml_stepwise(st.session_state['arch_explanation'], st.session_state['threat_model'], st.session_state['attack_paths'])
                        st.session_state['aml_file'] = aml_content
                    except Exception as e:
                        st.error(f"Failed to generate AutomationML file: {str(e)}")
            else:
                st.info("Generate an architectural explanation, threat model, and attack tree first, or upload a saved AutomationML file to proceed.")
        
        with col2:
            uploaded_aml = st.file_uploader(
                "Upload AutomationML file (.xml, .aml)", type=["xml", "aml"]
            )
            if uploaded_aml is not None:
                aml_content = uploaded_aml.read().decode("utf-8")
                st.session_state['aml_file'] = aml_content
                st.success("AutomationML file uploaded successfully.")

        if 'aml_file' in st.session_state:
            st.subheader("Generated AutomationML File")
            st.code(st.session_state['aml_file'], language='xml')
            st.download_button(
                label="Download AutomationML File",
                data=st.session_state['aml_file'],
                file_name="system_model.aml",
                mime="application/xml",
            )

#----------------------------------------------------------------------------------------------
# Analyse System Model and Compute Bayesian Probabilities
#----------------------------------------------------------------------------------------------

    with tab6:
        st.markdown("""
        Use this page to analyse system model attributes and calculate Bayesian probabilities of exposure and severe impact, along with the resulting risk assessment.
        """)
        st.markdown("""---""")

        if 'aml_file' in st.session_state:
            with st.container():
                col1, col2 = st.columns(2)

                with col1:
                        date_input = st.date_input(
                                    "Enter system installation date",
                                    date(2024, 1, 1),
                                    min_value=date(1900, 1, 1),
                                    max_value="today",
                                    format="DD/MM/YYYY")
                        if date_input > date.today():
                            st.error("The installation date cannot be in the future.")
                        else:
                            st.session_state['date_input'] = date_input
                        
                        if st.button("Load Model Attributes"):
                            load_model_attributes()
                            st.success("Attributes extracted successfully.")

                with col2:
                    if 'aml_attributes' in st.session_state:
                        st.session_state['start_node'] = st.selectbox(
                            "Attacker ID in the system model",
                            ("Attacker", "[U01] Attacker"),
                            index=1,
                            placeholder="Select or enter attacker ID",
                            accept_new_options=True,
                        )

                        st.session_state['af_modifier_input'] = st.slider(
                            "Attack Feasibility (AF) Modifier",
                            min_value=0.0,
                            max_value=1.0,
                            value=0.01,
                            step=0.01,
                            help="Adjust to factor attack feasibility (such as attacker skill, system security posture, etc.). "
                                "Higher value indicates a higher chance of a successful attack."
                        )

        else:
            st.info("Generate or upload an AutomationML model first to proceed with model analysis.")

    
        if 'aml_attributes' in st.session_state:
            ns = {'caex': 'http://www.dke.de/CAEX'}

            st.subheader("Asset Attributes")
            assets = st.session_state['aml_attributes']['assets']
            df_assets = pd.DataFrame(assets)
            edited_assets = st.data_editor(df_assets, num_rows="dynamic")
            updated_assets = edited_assets.to_dict(orient='records')
            asset_map = {asset['ID']: asset for asset in updated_assets}
            for internal_element in st.session_state['env'].element_tree_root.findall(".//caex:InternalElement", ns):
                asset_id = internal_element.attrib.get('ID')
                if asset_id and asset_id in asset_map:
                    updated = asset_map[asset_id]
                    idx = next((i for i, a in enumerate(st.session_state['aml_data'].AssetinSystem) if a['ID'] == asset_id), None)
                    for key, value in updated.items():
                        if key not in ['ID', 'Name', 'RefBaseSystemUnitPath']:
                            if idx is not None:
                                st.session_state['aml_data'].AssetinSystem[idx][key] = value

            st.subheader("Vulnerability Attributes")
            vulnerabilities = st.session_state['aml_attributes']['vulnerabilities']
            df_vuln = pd.DataFrame(vulnerabilities)
            cols = df_vuln.columns.tolist()
            if 'Attack Name' in cols:
                cols.remove('Attack Name')
                new_cols = ['Attack Name'] + cols
                df_vuln = df_vuln[new_cols]
            edited_vulns = st.data_editor(df_vuln, num_rows="dynamic")
            updated_vulns = edited_vulns.to_dict(orient='records')
            vuln_map = {vuln['ID']: vuln for vuln in updated_vulns}
            for internal_element in st.session_state['env'].element_tree_root.findall(".//caex:InternalElement", ns):
                vuln_id = internal_element.attrib.get('ID')
                if vuln_id and vuln_id in vuln_map:
                    updated = vuln_map[vuln_id]
                    idx = next((i for i, v in enumerate(st.session_state['aml_data'].VulnerabilityinSystem) if v['ID'] == vuln_id), None)
                    for key, value in updated.items():
                        if key not in ['ID', 'Name', 'RefBaseSystemUnitPath']:
                            if idx is not None:
                                st.session_state['aml_data'].VulnerabilityinSystem[idx][key] = value

            st.subheader("Hazard Attributes")
            hazards = st.session_state['aml_attributes']['hazards']
            df_hazards = pd.DataFrame(hazards)
            edited_hazards = st.data_editor(df_hazards, num_rows="dynamic")
            updated_hazards = edited_hazards.to_dict(orient='records')
            hazard_map = {hazard['ID']: hazard for hazard in updated_hazards}

            for internal_element in st.session_state['env'].element_tree_root.findall(".//caex:InternalElement", ns):
                hazard_id = internal_element.attrib.get('ID')
                if hazard_id and hazard_id in hazard_map:
                    updated = hazard_map[hazard_id]
                    idx = next((i for i, h in enumerate(st.session_state['aml_data'].HazardinSystem) if h['ID'] == hazard_id), None)
                    for key, value in updated.items():
                        if key not in ['ID', 'Name', 'RefBaseSystemUnitPath']:
                            if idx is not None:
                                st.session_state['aml_data'].HazardinSystem[idx][key] = value

#----------------------------------------------------------------------------------------------
# Placeholder for Decision Support Module
#----------------------------------------------------------------------------------------------

    with tab7:
        st.markdown("""
        Use this page to view and calibrate the countermeasure porfolio, which includes the probabilities of mitigation for each vulnerability in the system model.
        """)
        st.markdown("""---""")

        if 'aml_attributes' in st.session_state:
            st.subheader("Countermeasure Portfolio")
            vulnerabilities = st.session_state['aml_attributes']['vulnerabilities']
            df_vuln = pd.DataFrame(vulnerabilities)

            if 'Probability of Mitigation' not in df_vuln.columns:
                df_vuln['Probability of Mitigation'] = 0.0

            df_vuln_subset = df_vuln[['ID', 'Probability of Mitigation']]

            updated_probs = {}

            for index, row in df_vuln_subset.iterrows():
                prob = st.slider(
                    label=f"Vulnerability: {row['ID']}",
                    min_value=0.0,
                    max_value=1.0,
                    value=float(row['Probability of Mitigation']),
                    step=0.01,
                    key=f"slider_{row['ID']}_{index}"
                )
                updated_probs[row['ID']] = prob
        
            for internal_element in st.session_state['env'].element_tree_root.findall(".//caex:InternalElement", ns):
                vuln_id = internal_element.attrib.get('ID')
                if vuln_id in updated_probs:
                    prob = updated_probs[vuln_id]
                    idx = next((i for i, v in enumerate(st.session_state['aml_data'].VulnerabilityinSystem) if v['ID'] == vuln_id), None)
                    if idx is not None:
                        st.session_state['aml_data'].VulnerabilityinSystem[idx]['Probability of Mitigation'] = prob

            compute_bayesian_probabilities()

        else:
                st.info("Perform analysis first to proceed.")

    display_metrics()

if __name__ == "__main__":
    main()