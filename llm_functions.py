
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
from langchain_mistralai import ChatMistralAI
from langchain_google_genai import ChatGoogleGenerativeAI

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
    st.session_state['current_model_key'] = f"{new_provider}:{st.session_state['selected_model']}"

    # Set token limits from dict if existent, else fallback
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

def select_llm_model(model_provider):
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

