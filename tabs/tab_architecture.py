# Third-party imports
import streamlit as st
from langchain_mistralai import ChatMistralAI
from langchain_google_genai import ChatGoogleGenerativeAI

# Local application imports
from prompts import create_arch_narration_prompt

def tab_architectural_narration():
    st.title("ASTRAL (Architecture-Centric Security Threat Risk Assessment using Multimodal LLMs)")
    st.info("ASTRAL is an AI-powered tool designed to assist security professionals in generating architectural narrations, threat models, attack trees, and system models for cyber-physical systems (CPS). By leveraging multimodal large language models (LLMs), ASTRAL streamlines the process of identifying potential security threats, vulnerabilities, and risks within complex CPS architectures, and supports Bayesian and multi-objective decision support for CPS incident response.")
    st.markdown("""---""")
    #----------------------------------------------------------------------------------------------
    # Upload System Architecture Diagram
    #----------------------------------------------------------------------------------------------
    if 'api_key' not in st.session_state:
        st.sidebar.warning("Please enter your API key.")
        st.stop()

    uploaded_file = st.file_uploader(
        "Upload Architecture / Data Flow Diagram (DFD) Image", type=["png", "jpg", "jpeg", "bmp", "gif"]
    )

    if uploaded_file is not None:
        st.session_state['arch_filename'] = uploaded_file.name
        st.session_state['image_bytes'] = uploaded_file.read()
        st.image(st.session_state['image_bytes'], caption="Uploaded Image", width="stretch")
        arch_expl_prompt = create_arch_narration_prompt()

        if st.button("Generate Architectural Narration") and uploaded_file is not None:
            with st.spinner("Generating architectural narration..."):
                try:
                    if st.session_state['model_provider'] == "Mistral API":
                        client = ChatMistralAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model']
                        )
                    elif st.session_state['model_provider'] == "Gemini API":
                        client = ChatGoogleGenerativeAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model']
                        )
                    elif st.session_state['model_provider'] == "OpenAI API":
                        # add OpenAI call here if needed
                        pass
                    elif st.session_state['model_provider'] == "Anthropic API":
                        # add Anthropic call here if needed
                        pass

                    messages=[
                        {"role": "user", "content": arch_expl_prompt, "image": st.session_state['image_bytes']}
                    ]
                    response = client.invoke(messages)
                    st.session_state['arch_narration'] = response.content

                except Exception as e:
                    st.error(f"Failed to generate architectural narration: {str(e)}")
    else:
        st.warning("To get started, please upload an architecture or data flow diagram image of the CPS system.")

    #----------------------------------------------------------------------------------------------
    # Display Architectural Narration
    #----------------------------------------------------------------------------------------------
    if 'arch_narration' in st.session_state:
        st.subheader("Architectural Narration")
        st.write(st.session_state['arch_narration'])
        st.download_button(
            label="Download Architectural Narration",
            data=st.session_state['arch_narration'],
            file_name="arch_narration.md",
            mime="text/markdown",
        )
        additional_detail = st.text_area(
            "Enter Additional Architectural Details (Optional)",
            value="",
            key ="arch_additional_detail",
            placeholder="Enter extra architectural specifics here.",
            height=150,
        )

        #------------------------------------------------------------------------------------------
        # Re-Generate Architectural Narration with Additional Prompting
        #------------------------------------------------------------------------------------------
        if st.button("Re-Generate Architectural Narration"):
            with st.spinner("Generating architectural narration..."):
                try:
                    if st.session_state['model_provider'] == "Mistral API":
                        client = ChatMistralAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model'],
                            max_tokens=st.session_state['token_limit']
                        )
                    elif st.session_state['model_provider'] == "Gemini API":
                        client = ChatGoogleGenerativeAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model'],
                            max_tokens=st.session_state['token_limit']
                        )
                    elif st.session_state['model_provider'] == "OpenAI API":
                        # add OpenAI call here if needed
                        pass
                    elif st.session_state['model_provider'] == "Anthropic API":
                        # add Anthropic call here if needed
                        pass

                    messages=[
                        {"role": "user", "content": arch_expl_prompt + f"Additional architectural details: {additional_detail}", "image": st.session_state['image_bytes']}
                    ]
                    response = client.invoke(messages)
                    st.session_state['arch_narration'] = response.content
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Failed to generate architectural narration: {str(e)}")