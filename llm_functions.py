# Third-party imports
import streamlit as st
from azure.core.exceptions import ResourceNotFoundError
from langchain_mistralai import ChatMistralAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_deepseek import ChatDeepSeek
from langchain_openrouter import ChatOpenRouter

#----------------------------------------------------------------------------------------------
# Model Token Limits Dictionary
#----------------------------------------------------------------------------------------------
model_token_limits = {

    # Gemini models
    "Gemini:gemini-3.5-flash": {"default": 1048576, "max": 1048576},
    "Gemini:gemini-2.5-flash": {"default": 1048576, "max": 1048576},

    # Mistral models
    "Mistral:mistral-large-latest": {"default": 256000, "max": 256000},
    "Mistral:mistral-medium-latest": {"default": 128000, "max": 128000},

    # OpenAI models
    "OpenAI:gpt-5.4": {"default": 128000, "max": 128000},  

    # Claude models
    "Anthropic:claude-opus-4.7": {"default": 128000, "max": 128000},
    "Anthropic:claude-sonnet-4.6": {"default": 64000, "max": 64000},

    # OpenRouter models
    "OpenRouter:deepseek-v4-flash:free": {"default": 384000, "max": 384000},
    "OpenRouter:nemotron-nano-12b-v2-vl:free": {"default": 128000, "max": 128000},
}


#----------------------------------------------------------------------------------------------
# Callback Functions for Model Provider and Selection Changes
#----------------------------------------------------------------------------------------------
def on_model_provider_change():
    new_provider = st.session_state['model_provider']

    if new_provider == "Mistral":
        st.session_state['selected_model'] = "mistral-medium-latest"
    elif new_provider == "Gemini":
        st.session_state['selected_model'] = "gemini-2.5-flash"
    elif new_provider == "OpenAI":
        st.session_state['selected_model'] = "gpt-5.4"
    elif new_provider == "OpenRouter":
        st.session_state['selected_model'] = "deepseek/deepseek-v4-flash:free"
    elif new_provider == "Anthropic":
        st.session_state['selected_model'] = "claude-sonnet-4.6"

    st.session_state['current_model_key'] = f"{new_provider}:{st.session_state['selected_model']}"

    if st.session_state['current_model_key'] in model_token_limits:
        st.session_state['token_limit'] = model_token_limits[st.session_state['current_model_key']]["default"]
    else:
        st.session_state['token_limit'] = 8000  # Fallback default


def on_model_selection_change():
    if 'model_provider' not in st.session_state or 'selected_model' not in st.session_state:
        return
    
    st.session_state['current_model_key'] = f"{st.session_state['model_provider']}:{st.session_state['selected_model']}"

    if st.session_state['current_model_key'] in model_token_limits:
        st.session_state['token_limit'] = model_token_limits[st.session_state['current_model_key']]["default"]
    else:
        provider_key = f"{st.session_state['model_provider']}:default"
        if provider_key in model_token_limits:
            st.session_state['token_limit'] = model_token_limits[provider_key]["default"]

def select_llm_model():
    model_provider = st.selectbox(
    "Select your preferred model provider:",
    ["Mistral", "Gemini", "OpenRouter", "OpenAI", "Anthropic"],
    key="model_provider",
    index=0,
    on_change=on_model_provider_change,
    help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

    if model_provider == "Mistral":
        try:
            st.session_state['api_key'] = st.session_state['client'].get_secret("MISTRAL-API-KEY").value
        except ResourceNotFoundError:
            st.session_state['api_key'] = st.text_input("Mistral API Key", type="password")
        
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["mistral-medium-latest", "mistral-large-latest"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select the model you would like to use."
        )
        
    if model_provider == "Gemini":
        try:
            st.session_state['api_key'] = st.session_state['client'].get_secret("GEMINI-API-KEY").value
        except ResourceNotFoundError:
            st.session_state['api_key'] = st.text_input("Gemini API Key", type="password")
        
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gemini-3.5-flash", "gemini-2.5-flash"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select the model you would like to use."
        )

    if model_provider == "OpenAI":
        try:
            st.session_state['api_key'] = st.session_state['client'].get_secret("OPENAI-API-KEY").value
        except ResourceNotFoundError:
            st.session_state['api_key'] = st.text_input("OpenAI API Key", type="password")

        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["gpt-5.4"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select the model you would like to use."
        )

    if model_provider == "Anthropic":
        try:
            st.session_state['api_key'] = st.session_state['client'].get_secret("ANTHROPIC-API-KEY").value
        except ResourceNotFoundError:
            st.session_state['api_key'] = st.text_input("Anthropic API Key", type="password")

        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["claude-opus-4.7", "claude-sonnet-4.6"],
            key="selected_model",
            on_change=on_model_selection_change,
            help="Select the model you would like to use."
        )


    if model_provider == "OpenRouter":
        try:
            st.session_state['api_key'] = st.session_state['client'].get_secret("OPENROUTER-API-KEY").value
        except ResourceNotFoundError:
            st.session_state['api_key'] = st.text_input("OpenRouter API Key", type="password")

        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["deepseek/deepseek-v4-flash:free", "nvidia/nemotron-nano-12b-v2-vl:free"],
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


def init_client():
    if 'model_provider' not in st.session_state or 'selected_model' not in st.session_state:
        return None
    
    api_key = st.session_state.get('api_key', None)
    model_provider = st.session_state['model_provider']
    selected_model = st.session_state['selected_model']

    if model_provider == "Mistral":
        return ChatMistralAI(api_key=api_key, model=selected_model, max_tokens=st.session_state['token_limit'])
    elif model_provider == "Gemini":
        return ChatGoogleGenerativeAI(api_key=api_key, model=selected_model, max_tokens=st.session_state['token_limit'])
    elif model_provider == "OpenAI":
        # add OpenAI call here if needed
        pass
    elif model_provider == "Anthropic":
        # add Anthropic call here if needed
        pass
    elif model_provider == "OpenRouter":
        return ChatOpenRouter(api_key=api_key, model=selected_model, base_url="https://openrouter.ai/api/v1", max_tokens=st.session_state['token_limit'])