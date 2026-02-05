# Standard library imports
import ast
import glob
import os
import re
from concurrent.futures import ProcessPoolExecutor

# Third-party imports
import dill
import pandas as pd
import streamlit as st

# Local application imports
from prompts import *
from utils import *
from bayesian import *
from llm_functions import *

def tab_optimization():
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