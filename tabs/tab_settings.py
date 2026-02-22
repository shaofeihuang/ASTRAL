# Third-party imports
import streamlit as st
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Local application imports
from utils import *

def tab_settings():
    st.info("Use this tab to configure the settings for the ASTRAL tool, including LLM parameters and other preferences.")

    st.markdown("""---""")
    st.session_state['display_metrics'] = st.checkbox("Display Metrics", value=True, help="Toggle the display of metrics in the results.")
    st.session_state['debug_mode'] = st.checkbox("Debug Mode", value=True, help="Enable debug mode for more detailed error messages.")

    with st.expander("LLM Provider Settings", expanded=False):
        if st.checkbox("Azure Key Vault Integration", value=st.session_state.get('azure_key_vault_logged_in', False), help="Enable integration with Azure Key Vault for secure management of secrets and credentials."):
            if 'azure_key_vault_logged_in' in st.session_state:
                st.success(f"Already connected to Azure Key Vault: {st.session_state['azure_key_vault_logged_in']}")
                st.session_state['key_vault_name'] = st.text_input("Azure Key Vault Name", value=st.session_state['azure_key_vault_logged_in'] if 'azure_key_vault_logged_in' in st.session_state else "", help="Enter the name of your Azure Key Vault (without the .vault.azure.net suffix).")
            if st.button("Connect to Azure Key Vault"):
                key_vault_name = st.session_state.get("key_vault_name", "")
                key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
                credential = DefaultAzureCredential()
                st.session_state['client'] = SecretClient(vault_url=key_vault_uri, credential=credential)
                st.session_state['azure_key_vault_logged_in'] = key_vault_name
                st.success(f"Successfully connected to Azure Key Vault: {key_vault_name}")
        else:
            st.warning("Azure Key Vault integration is disabled. Please input credentials in the local .env file.")
            #---------------------- IMPORTANT!! ---------------------------
            # Uncomment to use .env file for local testing
            # load_dotenv()
            #--------------------------------------------------------------

    with st.expander("LLM Model Settings", expanded=True):
        st.session_state['llm_temperature'] = st.slider("Temperature", 0.0, 1.0, st.session_state['llm_temperature'], 0.05, help="Set the temperature for LLM responses. Higher values (e.g., 0.8) will make the output more creative, while lower values (e.g., 0.2) will make it more focused and deterministic.")
        st.session_state['llm_top_p'] = st.slider("top-p", 0.0, 1.0, st.session_state['llm_top_p'], 0.05, help="Set the nucleus sampling parameter (top-p) for LLM responses. This controls the diversity of the output by limiting the token selection to a subset of the most probable tokens whose cumulative probability exceeds the specified value.")
        st.session_state['llm_max_tokens'] = st.slider("Max Tokens", 100, 256000, st.session_state['token_limit'], 100, help="Set the maximum number of tokens for LLM responses. This limits the length of the generated output, which can help manage costs and ensure concise responses.")
        st.session_state['max_retries'] = st.slider("Max Retries", 0, 10, 5, help="Set the maximum number of retries for LLM API calls in case of failures or timeouts.")