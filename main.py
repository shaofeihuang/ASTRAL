# Standard library imports
import ast
import glob
import json
import logging
import os
import random
import re
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import date

# Third-party imports
import dill
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from anthropic import Anthropic
from mistralai import Mistral
from openai import OpenAI
from google import genai
from google.genai import types

# Local application imports
from prompts import *
from utils import *
from bayesian import *


#----------------------------------------------------------------------------------------------
# Model Token Limits Dictionary
#----------------------------------------------------------------------------------------------
model_token_limits = {

    # Gemini models
    "Gemini API:gemini-3-pro-preview": {"default": 1048576, "max": 1048576},
    "Gemini API:gemini-3-flash-preview": {"default": 1048576, "max": 1048576},
    "Gemini API:gemini-2.5-pro": {"default": 1048576, "max": 1048576},
    "Gemini API:gemini-2.5-flash": {"default": 1048576, "max": 1048576},

    # Mistral models
    "Mistral API:mistral-large-latest": {"default": 256000, "max": 256000},
    "Mistral API:mistral-medium-latest": {"default": 128000, "max": 128000},
    "Mistral API:mistral-small-latest": {"default": 128000, "max": 128000},
    "Mistral API:magistral-small-latest": {"default": 128000, "max": 128000},
    "Mistral API:magistral-medium-latest": {"default": 128000, "max": 128000},
    "Mistral API:ministral-8b-latest": {"default": 256000, "max": 256000},

    # OpenAI models
    "OpenAI API:gpt-5": {"default": 128000, "max": 400000},
    "OpenAI API:gpt-5-mini": {"default": 64000, "max": 400000},
    "OpenAI API:gpt-5-nano": {"default": 64000, "max": 400000},
    "OpenAI API:gpt-4.1": {"default": 128000, "max": 1000000},
    "OpenAI API:gpt-4o": {"default": 64000, "max": 128000},
    "OpenAI API:gpt-4o-mini": {"default": 64000, "max": 128000},
    "OpenAI API:o3": {"default": 64000, "max": 200000},
    "OpenAI API:o3-mini": {"default": 64000, "max": 200000},
    "OpenAI API:o4-mini": {"default": 64000, "max": 200000},    

    # Claude models
    "Anthropic API:claude-sonnet-4-5-20250929": {"default": 64000, "max": 200000},
    "Anthropic API:claude-sonnet-4-20250514": {"default": 64000, "max": 200000},
    "Anthropic API:claude-opus-4-1-20250805": {"default": 64000, "max": 200000},
    "Anthropic API:claude-opus-4-20250514": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-7-sonnet-latest": {"default": 64000, "max": 200000},
    "Anthropic API:claude-3-5-haiku-latest": {"default": 64000, "max": 200000},
}


#----------------------------------------------------------------------------------------------
# Callback Functions for Model Provider and Selection Changes
#----------------------------------------------------------------------------------------------
def on_model_provider_change():
    new_provider = st.session_state['model_provider']
    # Set default model per provider first
    if new_provider == "Mistral API":
        st.session_state['selected_model'] = "mistral-medium-latest"
    elif new_provider == "Gemini API":
        st.session_state['selected_model'] = "gemini-2.5-flash"
    elif new_provider == "OpenAI API":
        st.session_state['selected_model'] = "gpt-5"
    elif new_provider == "Anthropic API":
        st.session_state['selected_model'] = "claude-sonnet-4-5-20250929"

    # Compose correct key for lookup
    model_key = f"{new_provider}:{st.session_state['selected_model']}"

    # Set token limits from dict if existent, else fallback
    if model_key in model_token_limits:
        st.session_state['token_limit'] = model_token_limits[model_key]["default"]
    else:
        st.session_state['token_limit'] = 8000

    # Remove current model key
    if 'current_model_key' in st.session_state:
        del st.session_state['current_model_key']


def on_model_selection_change():
    if 'model_provider' not in st.session_state or 'selected_model' not in st.session_state:
        return
    
    model_key = f"{st.session_state['model_provider']}:{st.session_state['selected_model']}"

    if model_key in model_token_limits:
        st.session_state['token_limit'] = model_token_limits[model_key]["default"]
    else:
        provider_key = f"{st.session_state['model_provider']}:default"
        if provider_key in model_token_limits:
            st.session_state['token_limit'] = model_token_limits[provider_key]["default"]
    
    if 'current_model_key' in st.session_state:
        del st.session_state['current_model_key']


def call_mistral(api_key, prompt_text: str, image_bytes: bytes, model_name: str, max_tokens: int, response_as_json: bool = False):
    client = Mistral(api_key)
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

    return json.loads(content) if response_as_json else content


def call_gemini(api_key: str, prompt_text: str, image_bytes: bytes, 
                model_name: str, max_tokens: int, response_as_json: bool = False) -> str:
    client = genai.Client(api_key=api_key)
    
    text_part = types.Part(text=prompt_text)
    mime_type = (
        get_mime_type_from_filename(st.session_state.get('arch_filename', ''))
        if 'arch_filename' in st.session_state 
        else 'image/jpeg'
    )
    image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
    
    content = types.Content(role="user", parts=[text_part, image_part])
    
    if response_as_json:
        response = client.models.generate_content(
            model=model_name,
            contents=[content],
            config={"max_output_tokens": max_tokens, "response_mime_type": "application/json"}
        )
    else:
        response = client.models.generate_content(
            model=model_name,
            contents=[content],
            config={"max_output_tokens": max_tokens}
        )
    
    content = response.text
    return json.loads(content) if response_as_json else content


def call_openai(api_key, prompt_text: str, image_bytes: bytes, model_name: str, max_tokens: int, response_as_json: bool = False):
    client = OpenAI(api_key)

    # For reasoning models (o1, o3, o3-mini, o4-mini) and GPT-5 series models, use a structured system prompt
    if model_name in ["gpt-5", "gpt-5-mini", "gpt-5-nano", "o3", "o3-mini", "o4-mini"]:
        max_tokens = 20000 if model_name.startswith("gpt-5") else 8192
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": prompt_text, "image": image_bytes}
            ],
            max_completion_tokens=max_tokens
        )
    else:
        system_prompt = "You are a helpful assistant designed to output JSON."
        # Create completion with max_tokens for other models
        response = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": prompt_text, "image": image_bytes}
            ],
            max_tokens=8192
        )

    # Convert the JSON string in the 'content' field to a Python dictionary
    content = response.choices[0].message.content
    
    if not content:
        raise ValueError(f"Empty response from model {model_name}. This may indicate the model is not available or has rate limits.")

    return json.loads(content) if response_as_json else content


def call_anthropic(api_key, prompt_text: str, image_bytes: bytes, model_name: str, max_tokens: int, response_as_json: bool = False):
    client = Anthropic(api_key)
    
    is_claude_3_7 = "claude-3-7" in model_name.lower()
    is_thinking_mode = "thinking" in model_name.lower()
    
    actual_model = "claude-3-7-sonnet-latest" if is_thinking_mode else model_name
    
    try:
        if is_claude_3_7:
            json_prompt = prompt_text + "\n\nIMPORTANT: Your response MUST be a valid JSON object with the exact structure shown in the example above. Do not include any explanatory text, markdown formatting, or code blocks. Return only the raw JSON object."
            if is_thinking_mode:
                response = client.messages.create(
                    model=actual_model,
                    max_tokens=24000,
                    thinking={
                        "type": "enabled",
                        "budget_tokens": 16000
                    },
                    system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                    messages=[
                        {"role": "user", "content": json_prompt, "image": image_bytes}
                    ],
                    timeout=600  # 10-minute timeout
                )
            else:
                response = client.messages.create(
                    model=actual_model,
                    max_tokens=4096,
                    system="You are a JSON-generating assistant. You must ONLY output valid, parseable JSON with no additional text or formatting.",
                    messages=[
                        {"role": "user", "content": json_prompt, "image": image_bytes}
                    ],
                    timeout=300  # 5-minute timeout
                )
        else:
            # Standard handling for other Claude models
            response = client.messages.create(
                model=actual_model,
                max_tokens=4096,
                system="You are a helpful assistant designed to output JSON. Your response must be a valid, parseable JSON object with no additional text, markdown formatting, or explanation. Do not include ```json code blocks or any other formatting - just return the raw JSON object.",
                messages=[
                    {"role": "user", "content": prompt_text, "image": image_bytes}
                ],
                timeout=300  # 5-minute timeout
            )
        
        if is_thinking_mode:
            full_content = ''.join(block.text for block in response.content if block.type == "text")
            thinking_content = ''.join(block.thinking for block in response.content if block.type == "thinking")
            if thinking_content:
                st.session_state['last_thinking_content'] = thinking_content
        else:
            full_content = ''.join(block.text for block in response.content)
        
        try:
            if is_claude_3_7:
                full_content = full_content.replace(",\n  ]", "\n  ]").replace(",\n]", "\n]")
                full_content = re.sub(r'//.*?\n', '\n', full_content)
            
            response_content = json.loads(full_content)
            return response_content
        except json.JSONDecodeError as e:
            return e
            
    except Exception as e:
        # Handle timeout and other errors
        error_message = str(e)
        st.error(f"Error with Anthropic API: {error_message}")
        return e


#----------------------------------------------------------------------------------------------
# Main Application
#----------------------------------------------------------------------------------------------
def main():
    # Comment out if not using Azure Key Vault
    if 'azure_key_vault_logged_in' not in st.session_state:
        key_vault_name = "tra-demo"
        key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
        credential = DefaultAzureCredential()
        st.session_state['client'] = SecretClient(vault_url=key_vault_uri, credential=credential)
        st.session_state['azure_key_vault_logged_in'] = key_vault_name

    # Uncomment to use .env file for local testing
    # load_dotenv()

    with st.sidebar:
        st.image("logo.jpeg")
        model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["Mistral API", "Gemini API", "OpenAI API", "Anthropic API"],
        key="model_provider",
        index=0,
        on_change=on_model_provider_change,
        help="Select the model provider you would like to use. This will determine the models available for selection.",
        )

        #----------------------------------------------------------------------------------------------
        # Select Model based on Provider
        #----------------------------------------------------------------------------------------------

        if model_provider == "Mistral API":

            try:
                st.session_state['api_key'] = st.session_state['client'].get_secret("MISTRAL-API-KEY").value
            except ResourceNotFoundError:
                st.session_state['api_key'] = st.text_input("Mistral API Key", type="password")
            
            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["mistral-medium-latest", "mistral-large-latest", "mistral-small-latest", "magistral-medium-latest",
                 "magistral-small-latest", "ministral-8b-latest"],
                key="selected_model",
                on_change=on_model_selection_change,
                help="Select the model you would like to use."
            )
            
        if model_provider == "Gemini API":

            try:
                st.session_state['api_key'] = st.session_state['client'].get_secret("GEMINI-API-KEY").value
            except ResourceNotFoundError:
                st.session_state['api_key'] = st.text_input("Gemini API Key", type="password")
            
            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["gemini-3-pro-preview", "gemini-3-flash-preview", "gemini-2.5-pro", "gemini-2.5-flash"],
                key="selected_model",
                on_change=on_model_selection_change,
                help="Select the model you would like to use."
            )

        if model_provider == "OpenAI API":

            try:
                st.session_state['api_key'] = st.session_state['client'].get_secret("OPENAI-API-KEY").value
            except ResourceNotFoundError:
                st.session_state['api_key'] = st.text_input("OpenAI API Key", type="password")

            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-4.1", "gpt-4o", "gpt-4o-mini", "o3", "o3-mini", "o4-mini"],
                key="selected_model",
                on_change=on_model_selection_change,
                help="Select the model you would like to use."
            )

        if model_provider == "Anthropic API":

            try:
                st.session_state['api_key'] = st.session_state['client'].get_secret("ANTHROPIC-API-KEY").value
            except ResourceNotFoundError:
                st.session_state['api_key'] = st.text_input("Anthropic API Key", type="password")

            selected_model = st.selectbox(
                "Select the model you would like to use:",
                ["claude-sonnet-4-5-20250929", "claude-sonnet-4-20250514", "claude-opus-4-1-20250805", "claude-opus-4-20250514",
                 "claude-3-7-sonnet-latest", "claude-3-5-haiku-latest"],
                key="selected_model",
                on_change=on_model_selection_change,
                help="Select the model you would like to use."
            )

        #----------------------------------------------------------------------------------------------
        # Set token limit based on selected model
        #----------------------------------------------------------------------------------------------
        if 'token_limit' not in st.session_state:
            model_key = f"{model_provider}:{selected_model}"
            st.session_state['token_limit'] = model_token_limits[model_key]["default"]

        #----------------------------------------------------------------------------------------------
        # Select CPS System Context
        #----------------------------------------------------------------------------------------------
        system_context = st.selectbox(
            "CPS System Context",
            ["Cyber-Physical System", "Heating System", "Tesla IVI System", "Solar PV Inverter Panel", "Railway CBTC System", "Smart Grid System", "Smart Healthcare System", "Water Treatment System"],
            index=0,
            placeholder="Select or enter a custom description",
            accept_new_options=True,
        )

    #----------------------------------------------------------------------------------------------
    # Create Tabs for Different Functionalities
    #----------------------------------------------------------------------------------------------
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Architecture", "Threat Model", "Attack Tree", "System Model", "Bayesian Analysis", "Countermeasures", "Optimisation"])

#----------------------------------------------------------------------------------------------
# Generate Architectural Narration
#----------------------------------------------------------------------------------------------

    with tab1:
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
            image_bytes = uploaded_file.read()
            st.image(image_bytes, caption="Uploaded Image", width="stretch")
            arch_expl_prompt = create_arch_narration_prompt(system_context)

            if st.button("Generate Architectural Narration") and uploaded_file is not None:
                with st.spinner("Generating architectural narration..."):
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
                            st.session_state['arch_narration'] = model_output
                        elif model_provider == "Gemini API":
                            model_output = call_gemini(
                                st.session_state['api_key'],
                                arch_expl_prompt,
                                image_bytes,
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                            st.session_state['arch_narration'] = model_output
                        elif model_provider == "OpenAI API":
                            # add OpenAI call here if needed
                            pass
                        elif model_provider == "Anthropic API":
                            # add Anthropic call here if needed
                            pass
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
                placeholder="Enter extra architectural specifics here.",
                height=150,
            )

            #------------------------------------------------------------------------------------------
            # Re-Generate Architectural Narration with Additional Prompting
            #------------------------------------------------------------------------------------------
            if st.button("Re-Generate Architectural Narration"):
                with st.spinner("Generating architectural narration..."):
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
                            st.session_state['arch_narration'] = model_output
                            st.rerun()
                        elif model_provider == "Gemini API":
                            model_output = call_gemini(
                                st.session_state['api_key'],
                                arch_expl_prompt,
                                image_bytes,
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                            st.session_state['arch_narration'] = model_output
                            st.rerun()
                        elif model_provider == "OpenAI API":
                            # add OpenAI call here if needed
                            pass
                        elif model_provider == "Anthropic API":
                            # add Anthropic call here if needed
                            pass
                    except Exception as e:
                        st.error(f"Failed to generate architectural narration: {str(e)}")

#----------------------------------------------------------------------------------------------
# Generate Threat Model
#----------------------------------------------------------------------------------------------
    with tab2:
        st.info("Use this tab to generate a threat model tailored to the CPS system using the STRIDE-LM methodology, which expands upon the Microsoft STRIDE framework by including seven categories of threats: **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, **E**levation of Privilege, and **L**ateral **M**ovement. Architecture suggestions for improving the threat model will also be provided.")
        st.markdown("""---""")
        #----------------------------------------------------------------------------------------------
        # Create Threat Model Prompt
        #----------------------------------------------------------------------------------------------
        threat_model_prompt = create_threat_model_prompt(system_context)

        #----------------------------------------------------------------------------------------------
        # Generate Threat Model
        #----------------------------------------------------------------------------------------------
        if 'arch_narration' in st.session_state:
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
                            st.session_state['arch_suggestions'] = model_output.get("arch_suggestions", [])
                        elif model_provider == "Gemini API":
                            model_output = call_gemini(
                                st.session_state['api_key'],
                                threat_model_prompt,
                                image_bytes,
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=True
                                )
                            st.session_state['threat_model'] = model_output.get("threat_model", [])
                            st.session_state['arch_suggestions'] = model_output.get("arch_suggestions", [])
                        elif model_provider == "OpenAI API":
                            # add OpenAI call here if needed
                            pass
                        elif model_provider == "Anthropic API":
                            # add Anthropic call here if needed
                            pass
                    except Exception as e:
                        st.error(f"Failed to generate threat model: {str(e)}")
        else:
            st.warning("Generate an architectural narration first to proceed.")

        #----------------------------------------------------------------------------------------------
        # Display Threat Model
        #----------------------------------------------------------------------------------------------
        if 'threat_model' in st.session_state:
            markdown_output = tm_json_to_markdown(
                st.session_state['threat_model'],
                st.session_state.get('arch_suggestions', [])
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
# Generate Attack Trees and Attack Paths
#----------------------------------------------------------------------------------------------
    with tab3:
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
                            attack_tree_data = get_attack_tree(st.session_state['api_key'], model_provider, selected_model, attack_tree_prompt, system_context)
                            st.session_state['attack_tree_data'] = attack_tree_data
                            attack_tree = convert_tree_to_mermaid(attack_tree_data)
                            st.session_state['attack_tree'] = attack_tree
                            attack_paths = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
                            st.session_state['attack_paths'] = attack_paths
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
                attack_tree = convert_tree_to_mermaid(st.session_state['attack_tree_data'])
                st.session_state['attack_tree'] = attack_tree
                attack_paths = attack_tree_to_attack_paths(st.session_state['attack_tree_data'])
                st.session_state['attack_paths'] = attack_paths
        
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

#----------------------------------------------------------------------------------------------
# Generate System Model in AutomationML
#----------------------------------------------------------------------------------------------
    with tab4:
        st.info("Use this tab to generate a comprehensive AutomationML system model for the CPS architecture. The model will incorporate internal elements and links based on the architectural narration, threat model, and identified attack paths. You can also upload a previously saved AutomationML system model file in XML format.")
        st.markdown("""---""")

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
                        if model_provider == "Mistral API":
                            response_step1 = call_mistral(
                                st.session_state['api_key'],
                                prompt_step1,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                        elif model_provider == "Gemini API":
                            response_step1 = call_gemini(
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

            #------------------------------------------------------------------------------------------
            # Generate Valid Pairs based on Attack Paths
            #------------------------------------------------------------------------------------------
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
                        elif model_provider == "Gemini API":
                            response_step2 = call_gemini(
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
                        if model_provider == "Mistral API":
                            response_step3 = call_mistral(
                                st.session_state['api_key'],
                                prompt_step3,
                                image_bytes if 'image_bytes' in locals() else b'',
                                selected_model,
                                st.session_state['token_limit'],
                                response_as_json=False
                                )
                        elif model_provider == "Gemini API":
                            response_step3 = call_gemini(
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

            #------------------------------------------------------------------------------------------
            # Final Assembly of AutomationML Model
            #------------------------------------------------------------------------------------------
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
                        elif model_provider == "Gemini API":
                            response_step4 = call_gemini(
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

#----------------------------------------------------------------------------------------------
# Analyse System Model and Compute Bayesian Probabilities
#----------------------------------------------------------------------------------------------
    with tab5:
        st.info("Use this tab to analyse the generated AutomationML system model. Based on the model attributes, Bayesian probabilities of successful attacks will be computed to support risk assessment and decision-making. Enter the system installation date and load the model attributes to proceed with the analysis.")
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
                        
                        if st.button("Load/Reset Model Attributes"):
                            load_model_attributes()
                            st.success("Attributes extracted successfully. You can now adjust the attack feasibility (AF) modifier to incorporate attack characteristics in the analysis.")

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
                            value=0.5,
                            step=0.01,
                            help="Adjust to incorporate attack characteristics (such as attacker skill, system security posture, etc.). "
                                "Higher value indicates a higher chance of a successful attack."
                        )

        else:
            st.warning("Generate or upload an AutomationML model first to proceed with Bayesian analysis.")

        #----------------------------------------------------------------------------------------------
        # Data Tables for Model Attributes
        #----------------------------------------------------------------------------------------------
        if 'aml_attributes' in st.session_state:
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
# Calibrate Countermeasure Portfolio
#----------------------------------------------------------------------------------------------
    with tab6:
        st.info("Use this tab to view and calibrate the countermeasure portfolio, which includes the probabilities of mitigation for each vulnerability in the system model.")
        st.markdown("""---""")

        if 'aml_data' in st.session_state:
            st.subheader("Countermeasure Portfolio")

            if st.button("Refresh Values"):
                st.rerun()

            vulnerabilities = st.session_state['aml_data'].VulnerabilityinSystem
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

            # Save session state
            saved_session_state = {
                key: st.session_state[key]
                for key in st.session_state.keys()
            }
            with open("session.json", "wb") as f:
                dill.dump(saved_session_state, f)

            # Recompute risk
            compute_risk_score()

        else:
                st.warning("Perform Bayesian analysis first to proceed.")

#----------------------------------------------------------------------------------------------
# Multi-Objective Optimisation
#----------------------------------------------------------------------------------------------
    with tab7:
        st.info("Use this tab to perform multi-objective optimisation to identify optimal mitigation priority values for each vulnerability in the system model. The optimisation aims to minimize or maximize selected metrics simultaneously using Bayesian probabilities computed from the system model analysis.")
        st.markdown("""---""")

        if 'aml_attributes' in st.session_state:
            st.subheader("Multi-Objective Optimisation Parameters")
            n_trials = st.number_input("Number of Trials per Run", min_value=10, max_value=10000, value=1000, step=10)
            n_runs = st.number_input("Number of Optimisation Runs", min_value=1, max_value=20, value=1, step=1)

            if 'aml_data' in st.session_state:
                st.write("Number of vulnerabilitiies detected in model: {}".format(len(st.session_state['aml_data'].VulnerabilityinSystem)) )
            verbose = st.checkbox("Verbose Console Output", value=True)
            graph = st.checkbox("Show Optimisation Graph", value=False)
            objective = st.radio(
                "Optimisation Objectives",
                [
                    "Minimize Exposure & Impact Probabilities, Maximize Availability",
                    "Minimize Exposure & Impact Probabilities + Attack Tree Entropy",
                ],
                index=0,
            )

            if objective == "Minimize Exposure & Impact Probabilities, Maximize Availability":
                st.session_state['optimization_objective'] = 0
            elif objective == "Minimize Exposure & Impact Probabilities + Attack Tree Entropy":
                if 'attack_tree_data' not in st.session_state:
                    st.warning("Generate or upload an attack tree first to use Entropy as an optimisation objective.")
                st.session_state['optimization_objective'] = 1
            else:
                st.session_state['optimization_objective'] = 0  # Default

            if st.button("Start Optimisation"):
                files_to_remove = glob.glob("results-*.csv")
                for file_path in files_to_remove:
                    if os.path.exists(file_path):
                        os.remove(file_path)

                files_to_remove = glob.glob("202*.txt")
                for file_path in files_to_remove:
                    if os.path.exists(file_path):
                        os.remove(file_path)

                timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                st.session_state['output_filename'] = f"results-{timestamp}.csv"

                start_time = datetime.now()

                with st.spinner("Optimisation in progress... This may take several minutes."):
                    with ProcessPoolExecutor() as executor:
                        futures = [
                            executor.submit(run_study, n_trials, graph, verbose, st.session_state['output_filename'], st.session_state['optimization_objective'])
                            for run in range(n_runs)
                        ]
                        for future in futures:
                            future.result()  # Wait for all processes to complete

                total_time = datetime.now() - start_time  # Compute duration
                hours, remainder = divmod(total_time.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                st.success(f"Optimisation completed! Total execution time: {hours} hours {minutes} minutes {seconds} seconds")
                st.session_state['optimisation_done'] = True

            if st.session_state.get('optimisation_done', False):
                st.markdown("""---""")
                st.subheader("Optimisation Results")
                st.info("The table below summarises the mitigation priority values assigned to each vulnerability for the most Pareto-optimal trial in each optimisation run, along with the corresponding metrics.")

                df = pd.read_csv(st.session_state['output_filename'], header=None)
                v_headers = [f"V{str(i + 1).zfill(2)}" for i in range(len(df.columns) - 4)]
                if st.session_state['optimization_objective'] == 1:
                    new_header_row = v_headers + ["Best Trial ID", "Exposure", "Impact", "Entropy"]
                else:
                    new_header_row = v_headers + ["Best Trial ID", "Exposure", "Impact", "Availability"]
                df.columns = new_header_row
                df.insert(0, "Run ID", range(1, len(df) + 1))
                st.dataframe(df)
                st.markdown("""
                **Table explanation:**
                - Run ID: Unique identifier for each optimisation run.
                - V01, V02, ...: Mitigation priority values for each vulnerability (0 = highest priority, 1 = second highest, etc.).
                """)

                st.info("The bar chart below displays the average mitigation priority assigned to each vulnerability across Pareto-optimal solutions from the optimisation runs. Vulnerabilities with lower average values have been prioritised for mitigation more frequently, indicating higher mitigation importance.")

                v_columns = df.columns[1:-3]
                v_data = df[v_columns].apply(pd.to_numeric, errors='coerce')
                v_means = v_data.mean()
                st.bar_chart(v_means)

                st.info("You can visualise the mitigation effectiveness of the most Pareto-optimal trial from each optimisation run by selecting a Trial ID below. Higher parameter values indicate greater effectiveness of mitigation strategies against the corresponding vulnerabilities.")

                trial_ids = df.iloc[:, -4].dropna().astype(str).tolist()
                selected_trial_id = st.selectbox("Select a Trial ID", trial_ids)

                if selected_trial_id:
                    filename = f"{selected_trial_id}.txt"
                    if os.path.exists(filename):
                        # Parse trial parameters (only once)
                        params = None
                        with open(filename, "r") as file:
                            lines = file.readlines()
                            for line in lines:
                                if line.strip().startswith("Params:"):
                                    params_str = line.strip().split("Params:")[1].strip()
                                    params = ast.literal_eval(params_str)
                                    df_trials = pd.DataFrame([params], index=[selected_trial_id])
                                    st.bar_chart(df_trials.T)
                                    break
                        
                        if params is not None and st.button("Update Countermeasure Portfolio With Selected Trial Parameters"):
                            # Fix param key mapping: Mitigation_V01 → V01 vulnerability ID
                            updated_probs = {}
                            for param_key, prob_value in params.items():
                                # Extract vulnerability number from Optuna param name (Mitigation_V01 → V01)
                                if param_key.startswith("Mitigation_V"):
                                    vuln_num = param_key.replace("Mitigation_V", "V")
                                    vuln_num = vuln_num.zfill(2)  # Ensure V01, V02 format
                                    updated_probs[vuln_num] = float(prob_value)
                            
                            #print("[#] Updating Probabilities from Trial ID {}: {}".format(selected_trial_id, updated_probs))

                            # Update model
                            for internal_element in st.session_state['env'].element_tree_root.findall(".//caex:InternalElement", ns):
                                vuln_id = internal_element.attrib.get('ID')
                                match = re.match(r'\[(V\d+)\]', vuln_id)
                                if match:
                                    clean_vuln_id = match.group(1)  # "V02"
                                    if clean_vuln_id in updated_probs:
                                        prob = updated_probs[clean_vuln_id]
                                        #print("[#] Setting Vulnerability ID: {} to Probability of Mitigation: {:.2f}".format(clean_vuln_id, prob))
                                        idx = next((i for i, v in enumerate(st.session_state['aml_data'].VulnerabilityinSystem) 
                                                if extract_vuln_code(v['ID']) == clean_vuln_id), None)
                                        if idx is not None:
                                            #print("[#] Updating Vulnerability ID: {}, Probability of Mitigation: {:.2f}".format(clean_vuln_id, prob))
                                            st.session_state['aml_data'].VulnerabilityinSystem[idx]['Probability of Mitigation'] = prob
                            
                            #print(st.session_state['aml_data'].VulnerabilityinSystem)
                            
                            saved_session_state = {
                                key: st.session_state[key]
                                for key in st.session_state.keys()
                            }
                            with open("session.json", "wb") as f:
                                dill.dump(saved_session_state, f)

                        # Recompute risk
                        compute_risk_score() 
                        st.success("Countermeasure portfolio updated successfully!")
                    else:
                        st.warning(f"File {filename} does not exist.")

                else:
                    st.info("Select a trial ID to view its parameter values.")

        else:
                st.warning("Perform Bayesian analysis first to proceed.")

    display_metrics()

#----------------------------------------------------------------------------------------------
# Main Entry Point
#----------------------------------------------------------------------------------------------
if __name__ == "__main__":
    logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
    logging.getLogger('azure.identity').setLevel(logging.WARNING)
    main()