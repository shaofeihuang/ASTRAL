# Standard library imports
import logging

# Third-party imports
import streamlit as st
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Local application imports
from utils import *
from llm_functions import *
from tabs.tab_architecture import tab_architectural_narration
from tabs.tab_threat_model import tab_threat_model
from tabs.tab_attack_tree import tab_attack_tree
from tabs.tab_system_model import tab_system_model
from tabs.tab_bayesian_analysis import tab_bayesian_analysis
from tabs.tab_countermeasures import tab_countermeasures
from tabs.tab_optimisation import tab_optimisation
from tabs.tab_settings import tab_settings

def main():
    #---------------------- IMPORTANT!! ---------------------------
    # Comment out if not using Azure Key Vault
    #---------------------- IMPORTANT!! ---------------------------

    if 'azure_key_vault_logged_in' not in st.session_state:
        key_vault_name = st.session_state.get("key_vault_name", "tra-demo")
        key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
        credential = DefaultAzureCredential()
        st.session_state['client'] = SecretClient(vault_url=key_vault_uri, credential=credential)
        st.session_state['azure_key_vault_logged_in'] = key_vault_name

    #---------------------- IMPORTANT!! ---------------------------
    # Uncomment to use .env file for local testing
    # load_dotenv()
    #--------------------------------------------------------------
    
    # Initialize LLM model settings
    st.session_state['llm_temperature'] = 0.7
    st.session_state['llm_top_p'] = 0.9
    
    # Streamlit page configuration
    with st.sidebar:
        st.image("logo.jpeg")
        select_llm_model()

        st.session_state['system_context'] = st.selectbox(
            "CPS System Context",
            ["Cyber-Physical System", "Heating System", "Tesla IVI System", "Solar PV Inverter Panel", "Railway CBTC System", "Smart Grid System", "Smart Healthcare System", "Water Treatment System"],
            index=0,
            placeholder="Select or enter a custom description",
            accept_new_options=True,
        )

    tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(["Architecture", "Threat Model", "Attack Tree", "System Model", "Bayesian Analysis", "Countermeasures", "Optimisation", "Settings"])

    with tab1:
        tab_architectural_narration()

    with tab2:
        tab_threat_model(image_bytes=st.session_state.get('image_bytes', None))

    with tab3:
        tab_attack_tree()

    with tab4:
        tab_system_model()

    with tab5:
        tab_bayesian_analysis()

    with tab6:
        tab_countermeasures()

    with tab7:
        tab_optimisation()

    with tab8:
        tab_settings()

    if st.session_state.get('display_metrics', True):
        display_metrics()

#--------------------------------------------------------------------------------
# Main Entry Point
#--------------------------------------------------------------------------------

if __name__ == "__main__":
    logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
    logging.getLogger('azure.identity').setLevel(logging.WARNING)
    main()