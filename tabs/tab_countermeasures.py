# Third-party imports
import dill
import pandas as pd
import streamlit as st

# Local application imports
from utils import *


def tab_countermeasures():
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