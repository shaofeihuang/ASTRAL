from mistralai import Mistral
import json
import os
import time
import random
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from prompts import *
from utils import *
from bayesian import *

model_token_limits = {
    "mistral-large-latest": {"default": 64000, "max": 128000},
    "mistral-medium-latest": {"default": 64000, "max": 128000},
    "mistral-small-latest": {"default": 24000, "max": 32000},
    "magistral-small-latest": {"default": 32000, "max": 40000},
    "magistral-medium-latest": {"default": 32000, "max": 40000},
    "ministral-8b-latest": {"default": 64000, "max": 128000},
    "pixtral-12b-latest": {"default": 64000, "max": 128000},
}

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
        # Fallback: try to extract Mermaid code if JSON parsing fails
        return extract_mermaid_code(response.choices[0].message.content)


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

def main():
    load_dotenv()
    st.sidebar.image("logo.png")
    default_key = os.getenv("MISTRAL_API_KEY", "")
    api_key = st.sidebar.text_input("Mistral API Key", value=default_key, type="password")
    selected_model = st.sidebar.selectbox(
        "Select the model you would like to use:",
        list(model_token_limits.keys()),
        key="selected_model",
        help=(
            "Select a suitable model. Larger models may provide better results but can be slower and more costly."
        ),
    )
    max_tokens = model_token_limits[selected_model]["default"]

    system_context = st.sidebar.selectbox(
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

        if not api_key:
            st.sidebar.warning("Please enter your Mistral API key.")
            st.stop()

        uploaded_file = st.file_uploader(
            "Upload Architecture / Data Flow Diagram (DFD) Image", type=["png", "jpg", "jpeg", "bmp", "gif"]
        )

        if uploaded_file is not None:
            image_bytes = uploaded_file.read()
            st.image(image_bytes, caption="Uploaded Image", width="stretch")
            arch_expl_prompt = create_arch_expl_prompt(system_context)

            # Generate Architectural Explanation Button
            if st.button("Generate Architectural Explanation") and uploaded_file is not None:
                with st.spinner("Generating architectural explanation..."):
                    try:
                        model_output = call_mistral(
                            api_key, arch_expl_prompt, image_bytes, selected_model, max_tokens, response_as_json=False
                        )
                        st.session_state['arch_explanation'] = model_output
                    except Exception as e:
                        st.error(f"Failed to generate architectural explanation: {str(e)}")
        else:
            st.info("Please upload system architecture diagram.")

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
            additional_detail = st.text_area(
                "Additional Details (Optional)",
                value="",
                placeholder="Type extra architectural specifics here.",
                height=150,
            )
            # Re-Generate Architectural Explanation Button
            if st.button("Re-Generate Architectural Explanation"):
                with st.spinner("Generating architectural explanation..."):
                    try:
                        model_output = call_mistral(
                            api_key, arch_expl_prompt + "\n" + additional_detail.strip(), image_bytes, selected_model, max_tokens, response_as_json=False
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

        # Generate STRIDE-LM Threat Model Button
        if 'arch_explanation' in st.session_state:
            if st.button("Generate STRIDE-LM Threat Model"):
                with st.spinner("Generating STRIDE-LM threat model..."):
                    try:
                        model_output = call_mistral(
                            api_key, threat_model_prompt, image_bytes, selected_model, max_tokens, response_as_json=True
                        )
                        st.session_state['threat_model'] = model_output.get("threat_model", [])
                        st.session_state['improvement_suggestions'] = model_output.get("improvement_suggestions", [])
                    except Exception as e:
                        st.error(f"Failed to generate threat model: {str(e)}")
        else:
            st.info("Generate an architectural explanation first to proceed.")

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
                            st.session_state['dread_assessment'] = get_dread_assessment(api_key, selected_model, dread_assessment_prompt)
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
            if 'arch_explanation' in st.session_state and 'threat_model' in st.session_state:
                if st.button("Generate Attack Tree and Paths"):
                    attack_tree_prompt = at_json_to_markdown(st.session_state.get('arch_explanation'), st.session_state.get('threat_model'))
                    with st.spinner("Generating attack tree and paths..."):
                        try:
                            attack_tree_data = get_attack_tree(api_key, selected_model, attack_tree_prompt, system_context)
                            #print (attack_tree_data)
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
                        response_step1 = call_mistral(
                            api_key,
                            prompt_step1,
                            image_bytes if 'image_bytes' in locals() else b'',
                            selected_model,
                            max_tokens=max_tokens,
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
                        response_step2 = call_mistral(
                            api_key,
                            prompt_step2,
                            image_bytes if 'image_bytes' in locals() else b'',
                            selected_model,
                            max_tokens=max_tokens,
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
                        response_step3 = call_mistral(
                            api_key,
                            prompt_step3,
                            image_bytes if 'image_bytes' in locals() else b'',
                            selected_model,
                            max_tokens=max_tokens,
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
                        response_step4 = call_mistral(
                            api_key,
                            prompt_step4,
                            image_bytes if 'image_bytes' in locals() else b'',
                            selected_model,
                            max_tokens=max_tokens,
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
            if 'arch_explanation' in st.session_state and 'threat_model' in st.session_state and 'attack_paths' in st.session_state:
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

        with st.container():
            col1, col2, col3 = st.columns(3)

            with col1:
                if 'aml_file' in st.session_state:
                    if st.button("Load Model Attributes"):
                        aml_content = clean_aml_content(st.session_state['aml_file'])
                        assets, vulnerabilities, hazards = extract_attributes_from_aml(aml_content)
                        st.session_state['aml_attributes'] = {
                            'assets': assets,
                            'vulnerabilities': vulnerabilities,
                            'hazards': hazards
                        }
                        st.success("Attributes extracted successfully.")
                else:
                    st.info("Generate or upload an AutomationML model first to proceed with model analysis.")

            with col2:
                if 'aml_attributes' in st.session_state:
                    if st.button("Save Model Attributes"):
                        aml_content = clean_aml_content(st.session_state['aml_file'])
                        updated_aml = update_aml_from_attributes(aml_content, st.session_state['aml_attributes'])
                        st.session_state['aml_file'] = updated_aml
                        st.success("Attributes saved successfully.")

            with col3:
                if 'aml_attributes' in st.session_state:
                    start_node = st.selectbox(
                        "Attacker ID in the system model",
                        ("Attacker", "[U01] Attacker"),
                        index=1,
                        placeholder="Select or enter attacker ID",
                        accept_new_options=True,
                    )
                    af_modifier_input = st.slider(
                        "Attack Feasibility (AF) Modifier",
                        min_value=0.0,
                        max_value=1.0,
                        value=0.01,
                        step=0.01,
                        help="Adjust to factor attack feasibility (such as attacker skill, system security posture, etc.). "
                            "Lower values indicate a lower chance of a successful attack."
                    )

                    if st.button("Compute Bayesian Probabilities"):
                        aml_content = clean_aml_content(st.session_state['aml_file'])
                        env = Environment(*setup_environment(aml_content))
                        aml_data = AMLData(*process_AML_file(env.element_tree_root, env.t))
                        #check_probability_data(aml_data)
                        env.af_modifier = af_modifier_input
                        node_context = NodeContext(matching_asset_nodes=[], matching_hazard_nodes=[], matching_vulnerability_nodes=[], path_length_betn_nodes=[], path_length_betn_nodes_final=[], path_length_final_node=[])
                        bbn_exposure, last_node = create_bbn_exposure(aml_data, node_context, env.af_modifier)
                        bbn_impact = create_bbn_impact(bbn_exposure, aml_data, node_context)
                        check_bbn_models(bbn_exposure, bbn_impact)

                        inference_exposure = VariableElimination(bbn_exposure)
                        inference_impact = VariableElimination(bbn_impact)

                        if 'attack_paths' in st.session_state:
                            start_node = st.session_state['attack_paths'].split(" --> ")[0]
                            #last_node = st.session_state['attack_paths'].split(" --> ")[-1]

                        print ("[*] Start Node:", start_node, "\n[*] Last Node: ",last_node)

                        # Use this for debugging
                        # for index, element in enumerate(aml_data.total_elements):
                        #    print(f"Index: {index}, Element: {element}")

                        cpd_prob, cpd_impact = compute_risk_scores(inference_exposure, inference_impact, aml_data.total_elements, start_node, last_node)
                        # Use this for debugging if the compute_risk_scores function breaks
                        # cpd_prob = 0.5
                        # cpd_impact = 0.5

                        risk_score = cpd_prob * cpd_impact * 100
                        print('[*] Risk score: {:.2f} %'.format(risk_score))
                        print('--------------------------------------------------------')
                        if risk_score < 20:
                            print('[----] CPS System is under NEGLIGIBLE risk (less than 20%)')
                        elif 20 <= risk_score < 40:
                            print('[*---] CPS System is under LOW risk (between 20% and 40%)')
                        elif 40 <= risk_score < 60:
                            print('[**--] CPS System is under MEDIUM risk (between 40% and 60%)')
                        elif 60 <= risk_score < 80:
                            print('[***-] CPS System is under HIGH risk (between 60% and 80%)')
                        else:
                            print('[****] CPS System is under CRITICAL risk (greater than 80%)')

                        st.sidebar.metric("Posterior Probability of Exposure", value=f"{cpd_prob:.4f}")
                        st.sidebar.metric("Posterior Probability of Severe Impact", value=f"{cpd_impact:.4f}")
                        st.sidebar.metric("Risk Score", value=f"{risk_score:.2f}%")
        
        if 'aml_attributes' in st.session_state:
            st.subheader("Asset Attributes")
            assets = st.session_state['aml_attributes']['assets']
            df_assets = pd.DataFrame(assets)
            edited_assets = st.data_editor(df_assets, num_rows="dynamic")
            st.session_state['aml_attributes']['assets'] = edited_assets.to_dict(orient='records')
            print ("asset updated")

            st.subheader("Vulnerability Attributes")
            vulnerabilities = st.session_state['aml_attributes']['vulnerabilities']
            df_vuln = pd.DataFrame(vulnerabilities)
            cols = df_vuln.columns.tolist()
            if 'Attack Name' in cols:
                cols.remove('Attack Name')
                new_cols = ['Attack Name'] + cols
                df_vuln = df_vuln[new_cols]
            edited_vuln = st.data_editor(df_vuln, num_rows="dynamic")
            st.session_state['aml_attributes']['vulnerabilities'] = edited_vuln.to_dict(orient='records')
            print ("vuln updated")

            st.subheader("Hazard Attributes")
            hazards = st.session_state['aml_attributes']['hazards']
            df_hazards = pd.DataFrame(hazards)
            edited_hazards = st.data_editor(df_hazards, num_rows="dynamic")
            st.session_state['aml_attributes']['hazards'] = edited_hazards.to_dict(orient='records')

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

            # Add column if missing
            if 'Vulnerability.Probability of Mitigation' not in df_vuln.columns:
                df_vuln['Vulnerability.Probability of Mitigation'] = 0.0

            df_vuln_subset = df_vuln[['ID', 'Vulnerability.Probability of Mitigation']]

            updated_probs = []

            for index, row in df_vuln_subset.iterrows():
                prob = st.slider(
                    label=f"Vulnerability: {row['ID']}",
                    min_value=0.0,
                    max_value=1.0,
                    value=float(row['Vulnerability.Probability of Mitigation']),
                    step=0.01,
                    key=f"slider_{row['ID']}_{index}"
                )
                updated_probs.append(prob)

            # Update the original vulnerabilities list with new probabilities
            for i, prob in enumerate(updated_probs):
                st.session_state['aml_attributes']['vulnerabilities'][i]['Vulnerability.Probability of Mitigation'] = prob
        else:
                st.info("Perform analysis first to proceed.")


if __name__ == "__main__":
    main()