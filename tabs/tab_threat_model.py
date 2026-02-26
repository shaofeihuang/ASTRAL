# Standard library imports
import json

# Third-party imports
import streamlit as st
from langchain_mistralai import ChatMistralAI
from langchain_google_genai import ChatGoogleGenerativeAI

# Local application imports
from prompts import create_threat_model_prompt

# Convert threat model JSON to Markdown
def tm_json_to_markdown(threat_model, arch_suggestions):
    markdown_output = "## Threat Model\n\n"

    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"

    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"

    markdown_output += "\n\n## Architecture Suggestions\n\n"
    for suggestion in arch_suggestions:
        markdown_output += f"- {suggestion}\n"

    return markdown_output


def tab_threat_model():
    st.info("Use this tab to generate a threat model tailored to the CPS system using the STRIDE-LM methodology, which expands upon the Microsoft STRIDE framework by including seven categories of threats: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege, and **L**ateral **M**ovement. Architecture suggestions for improving the threat model will also be provided.")
    st.markdown("""---""")
    #----------------------------------------------------------------------------------------------
    # Create Threat Model Prompt
    #----------------------------------------------------------------------------------------------
    threat_model_prompt = create_threat_model_prompt()

    #----------------------------------------------------------------------------------------------
    # Generate Threat Model
    #----------------------------------------------------------------------------------------------
    if 'arch_narration' in st.session_state:
        if st.button("Generate STRIDE-LM Threat Model"):
            with st.spinner("Generating STRIDE-LM threat model..."):
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
                        {"role": "user", "content": threat_model_prompt, "image": st.session_state.get('image_bytes', None)}
                    ]
                    response = client.invoke(messages, response_format={"type": "json_object"})
                    model_output = json.loads(response.content)
                    st.session_state['threat_model'] = model_output.get("threat_model", [])
                    st.session_state['arch_suggestions'] = model_output.get("arch_suggestions", [])

                except Exception as e:
                    st.error(f"Failed to generate threat model: {str(e)}")
    else:
        st.warning("Generate an architectural narration first to proceed.")

    #----------------------------------------------------------------------------------------------
    # Display Threat Model
    #----------------------------------------------------------------------------------------------
    if 'threat_model' in st.session_state:
        st.markdown("""---""")
        
        markdown_output = tm_json_to_markdown(
            st.session_state['threat_model'],
            st.session_state.get('arch_suggestions', [])
        )
        st.subheader("Generated STRIDE-LM Threat Model")
        st.download_button(
            label="Download Threat Model",
            data=markdown_output,
            file_name="threat_model.md",
            mime="text/markdown",
        )
        st.markdown(markdown_output)
        additional_detail = st.text_area(
            "Enter Additional Architectural Details (Optional)",
            value="",
            key="threat_model_additional_detail",
            placeholder="Enter extra architectural specifics here.",
            height=150,
        )

        #------------------------------------------------------------------------------------------
        # Re-Generate Architectural Narration with Additional Prompting
        #------------------------------------------------------------------------------------------
        if st.button("Re-Generate Threat Model"):
            with st.spinner("Generating threat model..."):
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
                        {"role": "user", "content": threat_model_prompt + f"Additional architectural details: {additional_detail}", "image": st.session_state['image_bytes']}
                    ]
                    response = client.invoke(messages, response_format={"type": "json_object"})
                    model_output = json.loads(response.content)
                    st.session_state['threat_model'] = model_output.get("threat_model", [])
                    st.session_state['arch_suggestions'] = model_output.get("arch_suggestions", [])
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Failed to generate threat model: {str(e)}")