# Standard library imports
import csv
import dill
import os
import re
import mimetypes
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import asdict
import requests
import xml.etree.ElementTree as ET

# Third-party imports
import optuna
import streamlit as st

# Local application imports
from bayesian import *

# Namespace mapping for XML parsing
ns = {'caex': 'http://www.dke.de/CAEX'}

# Get MIME type from filename
def get_mime_type_from_filename(filename: str) -> str:
    """Guess MIME type from file extension, fallback to generic image."""
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type and mime_type.startswith('image/'):
        return mime_type
    return 'image/jpeg'  # Safe default for images


# Clean AML content by removing code block markers
def clean_aml_content(aml_file):
    aml_content = aml_file.strip()
    if aml_content.startswith("```xml"):
        aml_content = aml_content[len("```xml"):].strip()
    if aml_content.endswith("```"):
        aml_content = aml_content[:-len("```")].strip()
    aml_content = aml_content.replace('&', '&amp;')
    return aml_content


# Clean raw model response by extracting text content if it's a list of dicts, otherwise return as is
def clean_response(response):
    #print("[DEBUG] Raw response:", response)  # Debugging output
    if isinstance(response, list):
        print("------------------------------------------------------------------------------")
        print("[DEBUG] Response is a list. Attempting to extract text content from dict items.")
        print("------------------------------------------------------------------------------")
        for item in response:
            if isinstance(item, dict) and item.get("type") == "text":
                content = item.get("text", "")
                break
    elif hasattr(response, 'content'):
        print("-------------------------------------------------------------")
        print("[DEBUG] Response has 'content' attribute. Extracting content.")
        print("-------------------------------------------------------------")
        content = response.content
    else:
        print("----------------------------------------------------------------------------------------")
        print("[DEBUG] Response is not a list or does not have 'content' attribute. Using raw response.")  # Debugging output
        print("----------------------------------------------------------------------------------------")
        content = response

    #print ("[DEBUG] Cleaned content:", content)  # Debugging output
    return content


# Retrieve latest EPSS score for a CVE from FIRST.org
def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()["data"]
    if not data:
        return None
    return data[0]["epss"]


# Retrieve EPSS time series data for a CVE from FIRST.org
def get_epss_time_series(cve_id):
    """
    Retrieve EPSS time series data (daily) for a CVE from FIRST.org.
    If 'time-series' data is missing, falls back to the latest available score.
    Returns a list (even if only one value).
    """
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}&scope=time-series"
    response = requests.get(url)
    response.raise_for_status()
    data = response.json().get("data", [])
    epss_scores = []
    if data:
        if "time-series" in data[0] and data[0]["time-series"]:
            for entry in data[0]["time-series"]:
                epss_scores.append(entry["epss"])
        elif "epss" in data[0]:
            epss_scores.append(data[0]["epss"])
    return epss_scores


# Calculate Likely Exploited Vulnerability (LEV) probability from EPSS time series
def calculate_lev(epss_scores):
    """
    Calculate LEV probability from list of EPSS probabilities.
    """
    if not epss_scores:
        return None
    prob_no_exploit = 1.0
    window = len(epss_scores)
    for p in epss_scores:
        if window >= 30:
            weight = 1
        else:
            weight = window / 30
        prob_no_exploit *= (1 - float(p) *  weight)
    return 1 - prob_no_exploit


# Retrieve CVSS base score from NVD API v2
def get_cvss_score(cve_id, api_key=None):
    """Retrieve CVSS base score from NVD API v2."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    try:
        return data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    except (KeyError, IndexError):
        return None


# Check if CVE is in CISA KEV catalog
def check_kev_status(cve_id):
    """Check if CVE is in CISA KEV catalog."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    response.raise_for_status()
    kev_data = response.json()
    for item in kev_data.get("vulnerabilities", []):
        if item.get("cveID", "").upper() == cve_id.upper():
            return True
    return False


# Compute final exploitation probability using EPSS, LEV, and KEV data
def final_p_exposure(cve_id, api_key=None, verbose=False):
    if verbose:
        print("--------------------------------------------------------")
        print(f"Vulnerability Attributes for {cve_id}")
        print("Date:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("--------------------------------------------------------")

    # Retrieve CVSS score
    try:
        cvss_score = get_cvss_score(cve_id, api_key)
        if verbose:
            if cvss_score:
                print(f"CVSS v3.1 base score for {cve_id}: {cvss_score}")
            else:
                print(f"CVSS score not found for {cve_id}")
    except requests.HTTPError as err:
        print(f"Error retrieving CVSS score: {err}")

    if verbose:
        print("--------------------------------------------------------")

    # Retrieve and display EPSS time series
    epss_scores = get_epss_time_series(cve_id)
    if verbose:
        print(f"EPSS time series for {cve_id}: {epss_scores}")
  
    # Display latest EPSS score
    latest_epss = get_epss_score(cve_id)
    if verbose:
        if latest_epss:
            print(f"[*] Latest EPSS score for {cve_id}: {latest_epss}")
        else:
            print(f"[*] No latest EPSS score available for {cve_id}")
        print("--------------------------------------------------------")

    # Calculate LEV
    if epss_scores:
        lev_score = calculate_lev(epss_scores)
        if verbose:
            print(f"LEV score for {cve_id}: {lev_score:.4f} ({lev_score * 100:.4f}%)")
    else:
        lev_score = None
        if verbose:
            print(f"No EPSS time series data available for {cve_id}")

    if verbose:
        print("--------------------------------------------------------")

    # Check KEV status
    kev = check_kev_status(cve_id)
    if verbose:
        print(f"Is {cve_id} in KEV catalog?: {'Yes' if kev else 'No'}")
        print("--------------------------------------------------------")

    # Compute Exploitation Probability
    try:
        if kev:
            finalprob = 1.0
            if verbose:
                print(f"[*] Exploitation Probability for {cve_id} = 1.0 (KEV listed)")
        else:
            if lev_score is not None and (latest_epss is None or lev_score > float(latest_epss)):
                finalprob = lev_score
            elif latest_epss is not None:
                finalprob = float(latest_epss)
            else:
                finalprob = 0 #"N/A"
            if verbose:
                print(f"[*] Exploitation Probability for {cve_id} = {finalprob:.4f} ({finalprob * 100:.4f}%)")
    except Exception as e:
        if verbose:
            print(f"Error calculating exploitation probability: {e}")

    if verbose:
        print("--------------------------------------------------------")

    return finalprob


# Parse CVSS 3.1 vector into metrics
def parse_cvss_vector(vector):    
    # Handle full CVSS prefix and no-slash case
    if vector.startswith('CVSS:3.1/'):
        parts = vector[8:].split('/')
    elif vector.startswith('CVSS:3.1'):
        parts = vector[7:].split('/')
    else:
        parts = vector.split('/')
    
    # Remove empty parts and filter valid metric parts
    parts = [p.strip() for p in parts if ':' in p and len(p.split(':')) == 2]
    
    metrics = {}
    for part in parts:
        if ':' in part:
            metric, value = part.split(':', 1)
            if len(metric) >= 2 and len(value) >= 1:  # Valid metric format
                metrics[metric] = value
    
    return metrics


# Get numerical value for CVSS 3.1 metric
def get_metric_value(metric, value, scope='U'):
    """Get numerical value for CVSS 3.1 metric."""
    values = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
        'AC': {'L': 0.77, 'H': 0.44},
        'UI': {'N': 0.85, 'R': 0.62}
    }
    
    if metric == 'PR':
        pr_values = {
            'N': (0.85, 0.85),  # Unchanged, Changed
            'L': (0.62, 0.68),
            'H': (0.27, 0.50)
        }
        idx = 0 if scope == 'U' else 1
        return pr_values[value][idx]
    
    return values.get(metric, {}).get(value)


# Calculate p = AV x AC x PR x UI from CVSS vector
def calculate_p(vector):
    metrics = parse_cvss_vector(vector)
    
    if not metrics:
        return None, None, "Invalid CVSS 3.1 vector"
    
    scope = metrics.get('S', 'U')
    try:
        av = get_metric_value('AV', metrics['AV'], scope)
        ac = get_metric_value('AC', metrics['AC'], scope)
        pr = get_metric_value('PR', metrics['PR'], scope)
        ui = get_metric_value('UI', metrics['UI'], scope)
        
        p = av * ac * pr * ui
        return round(p, 2), metrics, None
    except (KeyError, TypeError):
        return None, metrics, "Missing or invalid metric values"


# Update exposure probabilities in AML content
def update_exposure_probabilities():
    aml_content = clean_aml_content(st.session_state['aml_file'])
    root = ET.fromstring(aml_content)
    internal_elements = root.findall(".//caex:InternalElement", ns)
    for internal_element in internal_elements:
        ref_base_system_unit_path = internal_element.get('RefBaseSystemUnitPath')
        if (ref_base_system_unit_path != 'VulnerabilityforSystem/Vulnerability'):
            continue
        else:
            cve = get_attribute_value(internal_element, 'CVE')
            # For CVE vulnerabilities, update Probability of Exposure using LEV/EPSS/CVSS/KEV data
            if re.match(r"CVE-\d{4}-\d{4,7}", cve):
                attribute_tag = internal_element.find(f".//caex:Attribute[@Name='Probability of Exposure']", ns)
                if attribute_tag is not None:
                    old_p = float(attribute_tag.find(f".//caex:Value", ns).text)
                    new_p = final_p_exposure(cve, verbose=False)
                    #new_p = 0.8888
                    attribute_tag.find(f".//caex:Value", ns).text = str(new_p)
                    element_id = internal_element.get('ID')
                    print("------------------------------------------------------------------------")
                    print(f"Element ID: {element_id}")
                    print(f"Updated {cve} Exposure Probability from {old_p} to {new_p}")
                    print("------------------------------------------------------------------------")

            # For non-CVE vulnerabilities, set EPSS to "N/A" and compute Bayesian confidence calibrated exposure probability from proxy CVSS vector
            else:
                # Set Probability of Exposure to "N/A" for non-CVE vulnerabilities
                epss_tag = internal_element.find(f".//caex:Attribute[@Name='EPSS']", ns)
                if epss_tag is not None:
                    epss_tag.find(f".//caex:Value", ns).text = "N/A"

                cvss_tag = internal_element.find(f".//caex:Attribute[@Name='CVSS']", ns)
                if cvss_tag is not None:
                    vector_value = cvss_tag.find(f".//caex:Value", ns).text
                    p, metrics, error = calculate_p(vector_value)
                    if error:
                        print(error)
                    else:
                        print("------------------------------------------------------------------------")
                        element_id = internal_element.get('ID')
                        print(f"Element ID: {element_id}")
                        print(f"CVSS vector: {vector_value}")
                        print(f"[*] P(Exposure) = AV({metrics['AV']}) x AC({metrics['AC']}) x PR({metrics['PR']}) x UI({metrics['UI']}) = {p}")

                        # Bayesian calibration with prior mean=0.5, prior variance=0.0025, likelihood variance=0.04
                        calibrated_p_mean = ((0.5/0.0025) + (p/0.04)) / (1/0.0025 + 1/0.04)
                        calibrated_p_variance = 1 / (1/0.0025 + 1/0.04)
                        calibrated_p_stddev = calibrated_p_variance ** 0.5
                        lower_bound = max(0, calibrated_p_mean - 1.96 * calibrated_p_stddev)
                        upper_bound = min(1, calibrated_p_mean + 1.96 * calibrated_p_stddev)
                        print(f"[*] Calibrated P(Exposure): Mean={calibrated_p_mean:.4f}, 95% CI=({lower_bound:.4f}, {upper_bound:.4f})")

                        attribute_tag = internal_element.find(f".//caex:Attribute[@Name='Probability of Exposure']", ns)
                        if attribute_tag is not None:
                            old_p = float(attribute_tag.find(f".//caex:Value", ns).text)
                            new_p = calibrated_p_mean
                            attribute_tag.find(f".//caex:Value", ns).text = str(new_p)
                            print(f"Updated Exposure Probability from {old_p} to {new_p}")
                        print("------------------------------------------------------------------------")

    st.session_state['aml_file'] = ET.tostring(root, encoding='unicode').replace('ns0:', '').replace('xmlns:ns0', 'xmlns').replace('&amp;', '&')
    return None


# Extract vulnerability code from ID string
def extract_vuln_code(id_str: str) -> str:
    match = re.match(r'\[(V\d+)\]', id_str)
    return match.group(1) if match else id_str.lstrip('V')


# Extract ID and Probability of Mitigation from AML data
def extract_id_mitigation():
    data_dict = asdict(st.session_state['aml_data'])
    
    result = {}
    for value in data_dict.values():
        if isinstance(value, list):
            for item in value:
                if (
                    isinstance(item, dict)
                    and "ID" in item
                    and "Probability of Mitigation" in item
                ):
                    result[item["ID"]] = item["Probability of Mitigation"]
    return result


# Calculate weighted entropy (1-mitigation) of attack tree from Mermaid syntax
def calculate_entropy(id_mitigation_dict):
    # Parse node definitions: id["description"]
    node_pattern = r'(\w+)\["([^"]*)"]'
    nodes = {}
    for match in re.finditer(node_pattern, st.session_state['attack_tree']):
        node_id = match.group(1)
        desc = match.group(2)
        nodes[node_id] = desc

    # Enrich nodes with mitigations (1 - mitigation for weighting)
    for node_id, desc in list(nodes.items()):
        id_match = re.search(r'\[(\w+)\]', desc)
        if id_match:
            node_code = id_match.group(1)
            target_key = next((k for k in id_mitigation_dict if k.startswith(f'[{node_code}]')), None)
            raw_mit = id_mitigation_dict.get(target_key, 0.0)
        else:
            raw_mit = 0.0
        mitigation = 1.0 - raw_mit  # Replace: (1 - mitigation) vulnerability/effort
        nodes[node_id] = {"description": desc, "mitigation": mitigation}  # Now stores (1-mit)
        #print(f"Node: {node_id}, Description: {desc}, Mitigation (1-raw): {mitigation}")

    # Parse edges: child --> parent (Mermaid BT top-down)
    edge_pattern = r'(\w+)\s*-->\s*(\w+)'
    edges = []
    for match in re.finditer(edge_pattern, st.session_state['attack_tree']):
        child = match.group(1)
        parent = match.group(2)
        edges.append((child, parent))

    # Build graph: parent -> children
    graph = defaultdict(list)
    for child, parent in edges:
        graph[parent].append(child)

    # t: terminal nodes (no children)
    terminal_nodes = [node for node in nodes if node not in graph or len(graph[node]) == 0]
    t = len(terminal_nodes)

    # Compute weighted degrees: degree * (1-mitigation) for each node
    degree_of = {}
    sequential_id = {}
    current_id = 1
    visited = set()

    if 'root_goal' in nodes:
        root = 'root_goal'
    elif 'root' in nodes:
        root = 'root'

    mit = nodes[root]["mitigation"]  # Now (1-raw_mit)
    degree_of[root] = 1 * mit
    sequential_id[root] = current_id
    current_id += 1
    visited.add(root)

    # BFS: propagate weighted depths
    if root in graph:
        queue = deque([root])
        while queue:
            node = queue.popleft()
            for child in graph[node]:
                if child not in visited:
                    child_mit = nodes[child]["mitigation"]  # (1-raw_mit)
                    degree_of[child] = degree_of[node] + (1 * child_mit)
                    sequential_id[child] = current_id
                    current_id += 1
                    visited.add(child)
                    queue.append(child)

    n = len(nodes)
    V = sum(degree_of.values())  # Sum of (1-mit) weighted depths
    m = len(edges)

    def entropy(V, m, degree_of, t):
        sum_term = 0.0
        for dn in degree_of.values():
            p = dn / V
            if p > 0:
                sum_term += p * math.log2(p)
        term1 = -(V / (2 * m)) * sum_term
        term2 = -(t / (2 * m)) * math.log2(V / (2 * m))
        H = term1 + term2
        return H

    H = entropy(V, m, degree_of, t)

    # Print counts and entropy
    #print("--------------------------------------------------------")
    #print("Attack Tree Metrics:")
    #print(f"n (nodes): {n}")
    #print(f"g (terminal nodes): {t}")
    #print(f"V (sum of degrees): {V}")
    #print(f"m (edges): {m}")
    #print(f"H (entropy): {H:.4f}")
    #print("--------------------------------------------------------")

    return H


# Load model attributes from AML file into session state
def load_model_attributes():
    aml_content = clean_aml_content(st.session_state['aml_file'])
    env = Environment(*setup_environment(aml_content))
    aml_data = AMLData(*process_AML_file(env.element_tree_root, env.t))
    st.session_state['aml_data'] = aml_data
    st.session_state['env'] = env
    st.session_state['aml_attributes'] = {
        'assets': aml_data.AssetinSystem,
        'vulnerabilities': aml_data.VulnerabilityinSystem,
        'hazards': aml_data.HazardinSystem
    }


# Compute risk score using Bayesian networks
def compute_risk_score():
    bbn_exposure, target_node = create_bbn_exposure()
    bbn_impact = create_bbn_impact()

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    start_node = st.session_state['start_node']

    if 'attack_paths' in st.session_state:
        start_node = st.session_state['attack_paths'].split(" --> ")[0]
        #last_node = st.session_state['attack_paths'].split(" --> ")[-1]

    print("[*] Start Node:", start_node)

    cpd_exposure, cpd_impact = compute_bayesian_probabilities(inference_exposure, inference_impact, start_node, target_node)

    risk_score = cpd_exposure * cpd_impact * 100
    availability = (1 - cpd_exposure) * (1 - cpd_impact) * 100
    st.session_state['cpd_exposure'] = cpd_exposure
    st.session_state['cpd_impact'] = cpd_impact
    st.session_state['risk_score'] = risk_score
    st.session_state['availability'] = availability
    print('--------------------------')
    print(datetime.now())
    print('--------------------------')
    print('[+] P(Exposure): {:.4f}'.format(cpd_exposure), 'P(Severe Impact): {:.4f}'.format(cpd_impact))
    print('[+] Risk score: {:.2f}%'.format(risk_score), 'System Availability: {:.2f}%'.format(availability))
    if 'attack_paths' in st.session_state:
        st.session_state['entropy'] = calculate_entropy(extract_id_mitigation())
        print('[+] Entropy of Attack Tree: {:.4f}'.format(st.session_state['entropy']))
    else:
        print('[!] Attack tree not generated yet. Entropy cannot be calculated.')


# Display risk metrics in sidebar
def display_metrics():
    st.sidebar.metric("Probability of Exposure", value=f"{st.session_state.get('cpd_exposure', 0):.4f}")
    st.sidebar.metric("Probability of Severe Impact", value=f"{st.session_state.get('cpd_impact', 0):.4f}")
    st.sidebar.metric("Risk Score", value=f"{st.session_state.get('risk_score', 0):.2f}%")
    st.sidebar.metric("System Availability", value=f"{st.session_state.get('availability', 0):.2f}%")
    st.sidebar.metric("Attack Entropy", value=f"{st.session_state.get('entropy', 0):.4f}")


# Objective functions for Optuna optimisation
def objective_availability(trial):
    mitigation_prob_dict = {}

    with open("session.json", "rb") as f:
        try:
            data = dill.load(f)
            st.session_state.update(data)
        except:
            st.session_state = {}

    n_vulns = len(st.session_state['aml_data'].VulnerabilityinSystem)
    
    mitigation_prob_dict = {str(i): trial.suggest_float(f'Mitigation_V{i:02d}', 0, 1) 
                           for i in range(1, n_vulns + 1)}

    for element in st.session_state['aml_data'].VulnerabilityinSystem:
        if (match := re.match(r'\[(?:V0*)(\d+)\]', element['ID'])):
            index = match.group(1).lstrip('0') or '0'
        else:
            index = element['ID'].lstrip('V') or '0'
        if index.isdigit() and (idx := int(index)) <= n_vulns:
            element['Probability of Mitigation'] = mitigation_prob_dict[index]

    return bbn_inference(st.session_state['start_node'])


def objective_entropy(trial):
    mitigation_prob_dict = {}

    with open("session.json", "rb") as f:
        try:
            data = dill.load(f)
            st.session_state.update(data)
        except:
            st.session_state = {}

    n_vulns = len(st.session_state['aml_data'].VulnerabilityinSystem)
    
    mitigation_prob_dict = {str(i): trial.suggest_float(f'Mitigation_V{i:02d}', 0, 1) 
                           for i in range(1, n_vulns + 1)}

    for element in st.session_state['aml_data'].VulnerabilityinSystem:
        if (match := re.match(r'\[(?:V0*)(\d+)\]', element['ID'])):
            index = match.group(1).lstrip('0') or '0'
        else:
            index = element['ID'].lstrip('V') or '0'
        if index.isdigit() and (idx := int(index)) <= n_vulns:
            element['Probability of Mitigation'] = mitigation_prob_dict[index]

    exposure, impact, _ = bbn_inference(st.session_state['start_node'])  # Ignore availability
    return exposure, impact, calculate_entropy(extract_id_mitigation())


# Run Optuna study for multi-objective optimisation
def run_study(n_trials, graph, verbose, output, optimisation_objective):
    # Extract run ID from output filename
    run_id, _ = os.path.splitext('-'.join(output.split('-')[1:3]))
    if optimisation_objective not in [0, 1]:
        raise ValueError("Invalid optimisation objective. Use 0 (Availability) or 1 (Entropy).")
    
    # Create Optuna study with appropriate directions
    directions = ["minimize", "minimize", "maximize"] if optimisation_objective == 0 else ["minimize", "minimize", "minimize"]
    study = optuna.create_study(directions=directions)
    study.optimize(objective_availability if optimisation_objective == 0 else objective_entropy, n_trials, timeout=300)

    # Generate Pareto front graph if requested    
    if graph:
        target_names = ["Exposure", "Impact", "Availability"] if optimisation_objective == 0 else ["Exposure", "Impact", "Entropy"]
        fig = optuna.visualization.plot_pareto_front(study, target_names=target_names)
        fig.show()
    
    # Identify best trial based on optimisation objective
    target_trials = study.best_trials
    best_trial = max(target_trials, key=lambda t: t.values[2]) if optimisation_objective == 0 else min(target_trials, key=lambda t: t.values[2])
    values = best_trial.values
    params = best_trial.params
    
    # Unified verbose output
    if verbose:
        metric_name = "Availability" if optimisation_objective == 0 else "Entropy"
        print(f"Run ID: {run_id}")
        print(f"Number of trials on the Pareto front: {len(target_trials)}")
        print(f"Trial with {'highest ' + metric_name.lower() if optimisation_objective == 0 else 'lowest ' + metric_name.lower()}:")
        print(f"\tTrial: {best_trial.number}")
        print(f"\tParams: {params}")
        print(f"\tExposure: {values[0]}, Impact: {values[1]}, {metric_name}: {values[2]}")
    
    # Unified file output
    best_trial_id = f"{run_id}-{datetime.now():%H%M%S}"
    best_trial_filename = f"{best_trial_id}.txt"
    metric_name = "Availability" if optimisation_objective == 0 else "Entropy"
    
    with open(best_trial_filename, "w", newline="") as file:
        file.write(f"Run ID: {run_id}\n")
        file.write(f"Number of trials on the Pareto front: {len(study.best_trials)}\n")
        file.write(f"Trial with {'highest ' if optimisation_objective == 0 else 'lowest '} {metric_name.lower()}:\n")
        file.write(f"Trial: {best_trial.number}\n")
        file.write(f"Params: {params}\n")
        file.write(f"Exposure: {values[0]}, Impact: {values[1]}, {metric_name}: {values[2]}\n")
    
    sorted_params = sorted(enumerate(params.values()), key=lambda item: item[1], reverse=True)
    sorted_indices = [item[0] for item in sorted_params]
    row = sorted_indices + [f"{best_trial_id}", f"{values[0]:.3f}", f"{values[1]:.3f}", f"{values[2]:.3f}"]
    
    with open(output, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(row)