import os
import json
import streamlit as st
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

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Architecture", "Threat Model", "Attack Tree", "AutomationML", "DREAD", "Mitigation"])

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
            arch_expl_prompt = create_arch_expl_prompt(system_context)

        # Generate Architectural Explanation Button
        if st.button("Generate Architectural Explanation", key="gen_arch_exp"):
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
        A threat model helps identify and evaluate potential security threats to applications / systems. It provides a systematic approach to 
        understanding possible vulnerabilities and attack vectors. Use this tab to generate a threat model using the STRIDE-LM methodology.
        """)
        st.markdown("""---""")
        threat_model_prompt = create_threat_model_prompt(system_context)
        
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
                    attack_tree = get_attack_tree(api_key, selected_model, attack_tree_prompt, system_context)
                    
                    # Save the generated code in session state
                    st.session_state['attack_tree'] = attack_tree
                    
                except Exception as e:
                    st.error(f"Error generating attack tree: {e}")
        
        # Check if we have saved code in session state to display
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
            st.error("Please generate an architectural explanation and threat model first.")


    with tab4:
        st.markdown("""
        Automation Markup Language (AutomationML) is an XML-based standard for representing industrial automation systems. It enables the exchange of information about system components,
        their relationships, and configurations. Generating an AutomationML file helps in documenting the system architecture and security considerations in a structured format.
        """)
        st.markdown("""---""")
        if st.button("Generate AutomationML File"):
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
                            max_tokens=max_tokens,  # adjust as needed
                            response_as_json=False
                        )
                        st.session_state['aml_file'] = aml_content
                    except Exception as e:
                        st.error(f"Failed to generate AutomationML file: {str(e)}")
            else:
                st.error("Please generate an architectural explanation, threat model, and attack tree first.")

        if 'aml_file' in st.session_state:
            st.subheader("Generated AutomationML File")
            st.code(st.session_state['aml_file'], language='xml')
            st.download_button(
                label="Download AutomationML File",
                data=st.session_state['aml_file'],
                file_name="system_model.aml",
                mime="application/xml",
            )


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