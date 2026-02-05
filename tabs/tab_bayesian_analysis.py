# Standard library imports
from datetime import date

# Third-party imports
import pandas as pd
import streamlit as st

# Local application imports
from utils import *

def tab_bayesian_analysis():
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