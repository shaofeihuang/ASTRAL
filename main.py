import os
import json
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from mistralai import Mistral
from prompts import *
from utils import *

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
        return convert_tree_to_mermaid(tree_data)
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
    system_context = st.sidebar.text_input(
        "Cyber-Physical System Context",
        value="Cyber-Physical System",
        placeholder="e.g. Solar PV inverter, ICS, etc.",
        help="Describe the specific cyber-physical system context for tailored threat modelling."
    )

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Architecture", "Threat Model", "Attack Tree", "AutomationML Model", "Attributes", "DREAD", "Mitigation"])

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
        if st.button("Generate Architectural Explanation", key="gen_arch_exp") and uploaded_file is not None:
            with st.spinner("Generating architectural explanation..."):
                try:
                    model_output = call_mistral(
                        api_key, arch_expl_prompt, image_bytes, selected_model, max_tokens, response_as_json=False
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
            additional_detail = st.text_area(
                "Add Additional Details (Optional)",
                value="",
                placeholder="Type extra architectural specifics here...",
                height=150,
            )
            # Re-Generate Architectural Explanation Button
            if st.button("Re-Generate Architectural Explanation", key="regen_arch_exp"):
                with st.spinner("Generating architectural explanation..."):
                    try:
                        model_output = call_mistral(
                            api_key, arch_expl_prompt + "\n" + additional_detail.strip(), image_bytes, selected_model, max_tokens, response_as_json=False
                        )
                        st.session_state['arch_explanation'] = model_output
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to generate architectural explanation: {str(e)}")


    with tab2:
        st.markdown("""
        A threat model helps identify and evaluate potential security threats to applications and systems. It provides a systematic approach to understanding possible vulnerabilities and attack vectors. The STRIDE-LM methodology expands upon the classic STRIDE framework by including seven categories of threats: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege, and **L**ateral **M**ovement. Using this method, you can comprehensively analyse your system to identify and prioritise security risks, enabling proactive mitigation. Use this tab to generate a threat model tailored to the CPS system using STRIDE-LM.
        """)
        st.markdown("""---""")
        threat_model_prompt = create_threat_model_prompt(system_context)
        
        # Generate STRIDE-LM Threat Model Button
        if st.button("Generate STRIDE-LM Threat Model", key="gen_threat_model") and st.session_state.get('arch_explanation'):
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
        else:
            st.info("Please generate an architectural explanation first.")

    with tab3:
        st.markdown("""
        Attack trees provide a systematic method to analyse the security of cyber-physical systems. They depict potential attack scenarios in a hierarchical structure, with the attacker’s ultimate objective at the root and various paths to reach that objective represented as branches. By illustrating attack paths and their impact on critical assets, attack trees support prioritisation of mitigation strategies and enhance real-time decision-making for system resilience.
        """)
        st.markdown("""---""")
        if selected_model == "mistral-small-latest":
            st.warning("⚠️ Mistral Small doesn't reliably generate syntactically correct Mermaid code. Please use the Mistral Large model for generating attack trees, or select a different model provider.")
            
        attack_tree_submit_button = st.button(label="Generate Attack Tree")
        
        if attack_tree_submit_button and st.session_state.get('threat_model'):
            attack_tree_prompt = at_json_to_markdown(st.session_state.get('arch_explanation'), st.session_state.get('threat_model'))
            with st.spinner("Generating attack tree..."):
                try:
                    attack_tree = get_attack_tree(api_key, selected_model, attack_tree_prompt, system_context)
                    st.session_state['attack_tree'] = attack_tree
                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")
        
        if 'attack_tree' in st.session_state:
            st.write("Attack Tree Code:")
            st.code(st.session_state['attack_tree'])
            st.write("Attack Tree Diagram Preview:")
            mermaid(st.session_state['attack_tree'])
            
            col1, col2, col3, col4, col5 = st.columns([1,1,1,1,1])
            
            with col1:              
                st.download_button(
                    label="Download Diagram Code",
                    data=st.session_state['attack_tree'],
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
            st.info("Please generate an architectural explanation and threat model first.")


    with tab4:
        st.markdown("""
        Automation Markup Language (AutomationML) is an XML-based open standard for representing industrial automation systems. It builds upon the CAEX (Computer Aided Engineering Exchange) format defined in IEC 62424, which provides an object-oriented data model for system components and their hierarchical relationships. AutomationML facilitates semantic interoperability across diverse CPS domains by enabling standardised, meaningful exchange of data about physical and cyber components, their configurations, and interrelations. Use this tab to generate an AutomationML representation of the CPS system.
        """)
        st.markdown("""---""")

        with st.container():
            col1, col2 = st.columns(2)

        with col1:
            if st.button("Generate AutomationML File"):
                st.session_state["upload_clicked"] = False
                if 'arch_explanation' in st.session_state and 'threat_model' in st.session_state and 'attack_tree' in st.session_state:
                    prompt = create_aml_prompt(
                        st.session_state['arch_explanation'],
                        st.session_state['threat_model'],
                        st.session_state['attack_tree']
                    )
                    with st.spinner("Generating AutomationML file..."):
                        try:
                            aml_content = call_mistral(
                                api_key,
                                prompt,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                max_tokens=max_tokens,
                                response_as_json=False
                            )
                            st.session_state['aml_file'] = aml_content
                        except Exception as e:
                            st.error(f"Failed to generate AutomationML file: {str(e)}")

        with col2:
            if st.button("Upload AutomationML File"):
                st.session_state["upload_clicked"] = True

        if st.session_state.get("upload_clicked", False):
            uploaded_aml = st.file_uploader(
                "Upload your AutomationML file", type=["xml", "aml"], key="upload_aml_file"
            )

            if uploaded_aml is not None:
                aml_content = uploaded_aml.read().decode("utf-8")
                st.session_state['aml_file'] = aml_content
                st.success("AutomationML file uploaded successfully.")
                st.code(st.session_state['aml_file'], language='xml')

        if 'aml_file' in st.session_state:
            st.subheader("Generated AutomationML File")
            st.code(st.session_state['aml_file'], language='xml')
            st.download_button(
                label="Download AutomationML File",
                data=st.session_state['aml_file'],
                file_name="system_model.aml",
                mime="application/xml",
            )
        elif not st.session_state.get("upload_clicked", False):
            st.info("Please generate an architectural explanation, threat model, and attack tree first.")


    with tab5:
        st.markdown("""

        """)
        st.markdown("""---""")

        with st.container():
            col1, col2 = st.columns(2)

            with col1:
                if st.button("Load Model Attributes"):
                    if st.session_state.get('aml_file'):
                        aml_content = clean_aml_content(st.session_state['aml_file'])
                        assets, vulnerabilities, hazards = extract_attributes_from_aml(aml_content)
                        st.session_state['aml_attributes'] = {
                            'assets': assets,
                            'vulnerabilities': vulnerabilities,
                            'hazards': hazards
                        }
                        st.success("Attributes extracted successfully.")
                    else:
                        st.info("You have unsaved edits. Please save them before reloading.")
            with col2:
                if st.button("Save Model Attributes"):
                    if st.session_state.get('aml_attributes'):
                        aml_content = clean_aml_content(st.session_state['aml_file'])
                        #print("AML Attributes\n--------------\n")
                        #print(st.session_state['aml_attributes'])
                        #print("\n\nAML File\n--------------\n")
                        #print(aml_content)
                        updated_aml = update_aml_from_attributes(aml_content, st.session_state['aml_attributes'])
                        st.session_state['aml_file'] = updated_aml
                        #print("Updated AML\n=================\n")
                        #print(updated_aml)
                        st.success("Attributes saved successfully.")

        if 'aml_attributes' in st.session_state:
            st.subheader("Asset Attributes")
            assets = st.session_state['aml_attributes']['assets']
            df_assets = pd.DataFrame(assets)
            edited_assets = st.data_editor(df_assets, num_rows="dynamic")          
            st.session_state['aml_attributes']['assets'] = edited_assets.to_dict(orient='records')

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

            st.subheader("Hazard Attributes")
            hazards = st.session_state['aml_attributes']['hazards']
            df_hazards = pd.DataFrame(hazards)
            edited_hazards = st.data_editor(df_hazards, num_rows="dynamic")
            st.session_state['aml_attributes']['hazards'] = edited_hazards.to_dict(orient='records')
            #if st.button("Compute Impact Ratings"):
                #code to compute impact ratings

        else:
            st.info("Please upload or generate an AutomationML model first.")




    with tab6:
        st.markdown("""
        DREAD is a structured methodology for evaluating and prioritising risks associated with security threats. It assesses each threat based on five criteria: **D**amage potential, **R**eproducibility, **E**xploitability, **A**ffected users, and **D**iscoverability. By scoring threats on these factors, organisations can calculate an overall risk level, which enables them to focus mitigation efforts on the most critical vulnerabilities first. This method supports consistent risk assessment, improves communication across teams, and helps allocate resources efficiently to protect systems effectively. Use this tab to perform a DREAD risk assessment for your application or system.
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

    with tab7:
        st.markdown("""
        Placeholder for mitigation strategies using real-time recommendations.
        """)
        st.markdown("""---""")


if __name__ == "__main__":
    main()