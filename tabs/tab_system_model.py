# Standard library imports
import random
import re
import time

# Third-party imports
import streamlit as st
from langchain_mistralai import ChatMistralAI
from langchain_google_genai import ChatGoogleGenerativeAI

# Local application imports
from prompts import *
from utils import *

#------------------------------------------------------------------------------------------
# Function to generate AutomationML in stepwise manner with retries
#------------------------------------------------------------------------------------------
def generate_aml_stepwise(arch_narration, threat_model, attack_paths):
    max_retries = 5

    #------------------------------------------------------------------------------------------
    # Generate Internal Elements based on Architectural Narration and Threat Model
    #------------------------------------------------------------------------------------------
    with st.spinner("Generating AutomationML Model (Step 1) ..."):
        for attempt in range(max_retries):
            try:
                print("[#] Generating AML - Step 1")
                start_time = time.time()

                prompt_step1 = create_aml_prompt_step_1(arch_narration, threat_model, attack_paths)

                try:
                    if st.session_state['model_provider'] == "Mistral API":
                        client = ChatMistralAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model'],
                            max_tokens=st.session_state['token_limit'],
                            max_retries=0
                        )
                    elif st.session_state['model_provider'] == "Gemini API":
                        client = ChatGoogleGenerativeAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model'],
                            max_tokens=st.session_state['token_limit'],
                            max_retries=0
                        )
                    elif st.session_state['model_provider'] == "OpenAI API":
                        # add OpenAI call here if needed
                        pass
                    elif st.session_state['model_provider'] == "Anthropic API":
                        # add Anthropic call here if needed
                        pass

                    internal_elements_xml = client.invoke(prompt_step1)

                except Exception as e:
                    st.error(f"Failed to generate internal elements XML: {str(e)}")

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

    #------------------------------------------------------------------------------------------
    # Generate Valid Pairs based on Attack Paths
    #------------------------------------------------------------------------------------------
    with st.spinner("Generating AutomationML Model (Step 2) ..."):
        for attempt in range(max_retries):
            try:
                print("[#] Generating AML - Step 2")
                start_time = time.time()

                prompt_step2 = create_aml_prompt_step_2(attack_paths)

                try:
                    if st.session_state['model_provider'] == "Mistral API":
                        client = ChatMistralAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model'],
                            max_tokens=st.session_state['token_limit'],
                            max_retries=0
                        )
                    elif st.session_state['model_provider'] == "Gemini API":
                        client = ChatGoogleGenerativeAI(
                            api_key=st.session_state['api_key'],
                            model=st.session_state['selected_model'],
                            max_tokens=st.session_state['token_limit'],
                            max_retries=0
                        )
                    elif st.session_state['model_provider'] == "OpenAI API":
                        # add OpenAI call here if needed
                        pass
                    elif st.session_state['model_provider'] == "Anthropic API":
                        # add Anthropic call here if needed
                        pass

                    valid_pairs_json = client.invoke(prompt_step2)

                except Exception as e:
                    st.error(f"Failed to generate valid pairs JSON: {str(e)}")

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

        #------------------------------------------------------------------------------------------
        # Generate Internal Links based on Valid Pairs
        #------------------------------------------------------------------------------------------
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

                    try:
                        if st.session_state['model_provider'] == "Mistral API":
                            client = ChatMistralAI(
                                api_key=st.session_state['api_key'],
                                model=st.session_state['selected_model'],
                                max_tokens=st.session_state['token_limit'],
                                max_retries=0
                            )
                        elif st.session_state['model_provider'] == "Gemini API":
                            client = ChatGoogleGenerativeAI(
                                api_key=st.session_state['api_key'],
                                model=st.session_state['selected_model'],
                                max_tokens=st.session_state['token_limit'],
                                max_retries=0
                            )
                        elif st.session_state['model_provider'] == "OpenAI API":
                            # add OpenAI call here if needed
                            pass
                        elif st.session_state['model_provider'] == "Anthropic API":
                            # add Anthropic call here if needed
                            pass

                        internal_links_xml = client.invoke(prompt_step3)

                    except Exception as e:
                        st.error(f"Failed to generate internal links XML: {str(e)}")

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

        #------------------------------------------------------------------------------------------
        # Final Assembly of AutomationML Model
        #------------------------------------------------------------------------------------------
        with st.spinner("Generating AutomationML Model (Step 4) ..."):
            for attempt in range(max_retries):
                try:
                    print("[#] Generating AML - Step 4 (Final)")
                    start_time = time.time()
                    prompt_step4 = create_aml_prompt_step_4(internal_elements_xml, internal_links_xml)

                    try:
                        if st.session_state['model_provider'] == "Mistral API":
                            client = ChatMistralAI(
                                api_key=st.session_state['api_key'],
                                model=st.session_state['selected_model'],
                                max_tokens=st.session_state['token_limit'],
                                max_retries=0
                            )
                        elif st.session_state['model_provider'] == "Gemini API":
                            client = ChatGoogleGenerativeAI(
                                api_key=st.session_state['api_key'],
                                model=st.session_state['selected_model'],
                                max_tokens=st.session_state['token_limit'],
                                max_retries=0
                            )
                        elif st.session_state['model_provider'] == "OpenAI API":
                            # add OpenAI call here if needed
                            pass
                        elif st.session_state['model_provider'] == "Anthropic API":
                            # add Anthropic call here if needed
                            pass

                        final_aml_xml = client.invoke(prompt_step4)

                    except Exception as e:
                        st.error(f"Failed to generate final AML XML: {str(e)}")
                        
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

        return final_aml_xml


def tab_system_model():
    st.info("Use this tab to generate a comprehensive AutomationML system model for the CPS architecture. The model will incorporate internal elements and links based on the architectural narration, threat model, and identified attack paths. You can also upload a previously saved AutomationML system model file in XML format.")
    st.markdown("""---""")

    with st.container():
        col1, col2 = st.columns(2)

        with col1:
            if all(key in st.session_state for key in ("arch_narration", "threat_model", "attack_paths")):
                if st.button("Generate AutomationML File"):
                    try:
                        st.warning("Generating the AutomationML system model may take several minutes depending on the complexity of the architecture and threat model. Please be patient. You may see intermittent warnings about retries - these are normal and indicate the system is handling transient issues with the model provider.")
                        aml_content = generate_aml_stepwise(st.session_state['arch_narration'], st.session_state['threat_model'], st.session_state['attack_paths'])
                        aml_content = clean_aml_content(aml_content)
                        st.session_state['aml_file'] = aml_content
                    except Exception as e:
                        st.error(f"Failed to generate AutomationML file: {str(e)}")
            else:
                st.warning("Generate an architectural narration, threat model, and attack tree first, or upload a previously saved AutomationML file to proceed.")

        with col2:
            uploaded_aml = st.file_uploader(
                "Upload AutomationML file (.xml, .aml)", type=["xml", "aml"]
            )
            if uploaded_aml is not None and 'aml_file' not in st.session_state:
                aml_content = uploaded_aml.read().decode("utf-8")
                aml_content = clean_aml_content(aml_content)
                st.session_state['aml_file'] = aml_content
                st.success("AutomationML file uploaded successfully.")

        if 'aml_file' in st.session_state:
            st.info("Click on the 'Update Exposure Probabilities' button after generating the system model to update the vulnerability exposure probabilities.")

            st.subheader("Generated AutomationML File")

            # Update Exposure Probabilities
            if st.button("Update Exposure Probabilities"):
                with st.spinner("Updating exposure probabilities..."):
                    update_exposure_probabilities()
                    st.success("Exposure probabilities updated successfully.")

            # Download AutomationML File
            st.download_button(
                label="Download AutomationML File",
                data=st.session_state['aml_file'],
                file_name="system_model.aml",
                mime="application/xml",
            )

            # Display AutomationML File Content
            st.code(st.session_state['aml_file'], language='xml')
