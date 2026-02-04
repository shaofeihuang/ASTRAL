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
from llm_functions import *
from tabs.tab_architecture import tab_architectural_narration
from tabs.tab_threat_model import tab_threat_model
from tabs.tab_attack_tree import tab_attack_tree
from tabs.tab_system_model import tab_system_model

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

    #----------------- IMPORTANT!! ----------------
    # Uncomment to use .env file for local testing
    # load_dotenv()
    #----------------------------------------------

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
        # Select LLM Model
        #----------------------------------------------------------------------------------------------
        select_llm_model(model_provider)

        #----------------------------------------------------------------------------------------------
        # Select CPS System Context
        #----------------------------------------------------------------------------------------------
        st.session_state['system_context'] = st.selectbox(
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
        tab_architectural_narration()

#----------------------------------------------------------------------------------------------
# Generate Threat Model
#----------------------------------------------------------------------------------------------
    with tab2:
        tab_threat_model(image_bytes=st.session_state.get('image_bytes', None))

#----------------------------------------------------------------------------------------------
# Generate Attack Trees and Attack Paths
#----------------------------------------------------------------------------------------------
    with tab3:
        tab_attack_tree()

#----------------------------------------------------------------------------------------------
# Generate System Model in AutomationML
#----------------------------------------------------------------------------------------------
    with tab4:
        tab_system_model()

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
            graph = st.checkbox("Show Optimisation Graph", value=True)
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