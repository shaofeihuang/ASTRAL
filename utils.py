from io import StringIO
import json, re, requests
import streamlit as st
import streamlit.components.v1 as components
import xml.etree.ElementTree as ET
from datetime import datetime
from bayesian import *
from prompts import *
from mistralai import Mistral
from anthropic import Anthropic
from openai import OpenAI


# Namespace mapping for XML parsing
ns = {'caex': 'http://www.dke.de/CAEX'}

# Utility Functions

# Clean AML content by removing code block markers
def clean_aml_content(aml_file):
    aml_content = aml_file.strip()
    if aml_content.startswith("```xml"):
        aml_content = aml_content[len("```xml"):].strip()
    if aml_content.endswith("```"):
        aml_content = aml_content[:-len("```")].strip()
    return aml_content


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
    """
    Parse CVSS 3.1 vector and return dict of metrics.
    
    Args:
        vector (str): Full CVSS vector string
        
    Returns:
        dict: Metrics like {'AV': 'N', 'AC': 'L', ...} or None if invalid
    """
    # Regex matches metric: AV:N, AC:L, etc.
    pattern = r'CVSS:3\.1/([A-Z]+:[A-Z])(/[A-Z]+:[A-Z])*'
    if not re.match(pattern, vector):
        return None
    
    metrics = {}
    # Split after version prefix
    parts = vector.split('/')[1:]
    for part in parts:
        if ':' in part:
            metric, value = part.split(':', 1)
            metrics[metric] = value
    
    required = {'AV', 'AC', 'PR', 'UI'}
    if not required.issubset(metrics):
        return None
    
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
    """
    Calculate p = AV x AC x PR x UI from CVSS vector.
    
    Returns:
        tuple: (p_value, metrics_dict, error_msg)
    """
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
            # For CVE vulnerabilities, update Probability of Exposure using LEV/EPSS/KEV data
            if re.match(r"CVE-\d{4}-\d{4,7}", cve):
                attribute_tag = internal_element.find(f".//caex:Attribute[@Name='Probability of Exposure']", ns)
                if attribute_tag is not None:
                    old_p = float(attribute_tag.find(f".//caex:Value", ns).text)
                    new_p = final_p_exposure(cve, verbose=False)
                    attribute_tag.find(f".//caex:Value", ns).text = str(new_p)
                    print(f"Updated {cve} Exposure Probability from {old_p} to {new_p}")

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
                        print(f"Vector: {vector_value}")
                        print(f"Metrics: {metrics}")
                        print(f"p = AV({metrics['AV']}) x AC({metrics['AC']}) x PR({metrics['PR']}) x UI({metrics['UI']}) = {p}")

                        calibrated_p_mean = ((0.5/0.0025) + (p/0.04)) / (1/0.0025 + 1/0.04)
                        calibrated_p_variance = 1 / (1/0.0025 + 1/0.04)
                        calibrated_p_stddev = calibrated_p_variance ** 0.5
                        lower_bound = max(0, calibrated_p_mean - 1.96 * calibrated_p_stddev)
                        upper_bound = min(1, calibrated_p_mean + 1.96 * calibrated_p_stddev)
                        print(f"Calibrated p: Mean={calibrated_p_mean:.4f}, 95% CI=({lower_bound:.4f}, {upper_bound:.4f})")

                
        
    st.session_state['aml_file'] = ET.tostring(root, encoding='unicode').replace('ns0:', '').replace('xmlns:ns0', 'xmlns')
    return None


# Clean JSON response from code block markers
def clean_json_response(response_text):
    json_pattern = r'```json\s*(.*?)\s*```'
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    code_pattern = r'```\s*(.*?)\s*```'
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return response_text.strip()


# Convert threat model JSON to Markdown
def tm_json_to_markdown(threat_model, improvement_suggestions):
    markdown_output = "## Threat Model\n\n"

    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"

    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"

    markdown_output += "\n\n## Improvement Suggestions\n\n"
    for suggestion in improvement_suggestions:
        markdown_output += f"- {suggestion}\n"

    return markdown_output


# Convert architecture narration and threat model JSON to Markdown
def at_json_to_markdown(arch_narration, threat_model):
    markdown_output = "## Architecture narration\n\n"

    markdown_output += arch_narration + "\n\n"

    markdown_output += "## Threat Model\n\n"

    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"

    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"

    return markdown_output


# Convert DREAD assessment JSON to Markdown
def dread_json_to_markdown(dread_assessment):
    # Create a clean Markdown table with proper spacing
    markdown_output = "| Threat Type | Scenario | Damage Potential | Reproducibility | Exploitability | Affected Users | Discoverability | Risk Score |\n"
    markdown_output += "|------------|----------|------------------|-----------------|----------------|----------------|-----------------|------------|\n"

    try:
        # Access the list of threats under the "Risk Assessment" key
        threats = dread_assessment.get("Risk Assessment", [])

        # If there are no threats, add a message row
        if not threats:
            markdown_output += "| No threats found | Please generate a threat model first | - | - | - | - | - | - |\n"
            return markdown_output

        for threat in threats:
            # Check if threat is a dictionary
            if isinstance(threat, dict):
                # Get values with defaults
                threat_type = threat.get('Threat Type', 'N/A')
                scenario = threat.get('Scenario', 'N/A')
                damage_potential = threat.get('Damage Potential', 0)
                reproducibility = threat.get('Reproducibility', 0)
                exploitability = threat.get('Exploitability', 0)
                affected_users = threat.get('Affected Users', 0)
                discoverability = threat.get('Discoverability', 0)

                # Calculate the Risk Score
                risk_score = (damage_potential + reproducibility + exploitability + affected_users + discoverability) / 5

                # Escape any pipe characters in text fields to prevent table formatting issues
                threat_type = str(threat_type).replace('|', '\\|')
                scenario = str(scenario).replace('|', '\\|')

                # Ensure scenario text doesn't break table formatting by removing newlines
                scenario = scenario.replace('\n', ' ').replace('\r', '')

                # Add the row to the table with proper formatting
                markdown_output += f"| {threat_type} | {scenario} | {damage_potential} | {reproducibility} | {exploitability} | {affected_users} | {discoverability} | {risk_score:.2f} |\n"
            else:
                # Skip non-dictionary entries and log a warning
                markdown_output += "| Invalid threat | Threat data is not in the correct format | - | - | - | - | - | - |\n"
    except Exception as e:
        # Add a note about the error and a placeholder row
        markdown_output += "| Error | An error occurred while processing the DREAD assessment | - | - | - | - | - | - |\n"

    # Add a blank line after the table for better rendering
    markdown_output += "\n"
    return markdown_output


# Create JSON schema for attack tree
def create_attack_tree_schema():
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "$ref": "#/$defs/node"
                        }
                    }
                },
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node"
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal"
                            },
                            "children": {
                                "type": "array",
                                "items": {
                                    "$ref": "#/$defs/node"
                                }
                            }
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False
            },
            "strict": True
        }
    }


# Convert attack tree JSON to attack paths
def attack_tree_to_attack_paths(tree_data):
    attack_path_lines = []

    def process_node(node, path_labels):
        # Add current node label only (omit node ID)
        path_labels = path_labels + [node["label"]]

        # If leaf node, add reversed attack path (from attacker to goal)
        if not node.get("children"):
            reversed_labels = list(reversed(path_labels))
            attack_path_lines.append(" --> ".join(reversed_labels))
        else:
            for child in node["children"]:
                process_node(child, path_labels)

    for root_node in tree_data["nodes"]:
        process_node(root_node, [])

    return "\n".join(attack_path_lines)


# Convert attack tree JSON to Mermaid syntax
def convert_tree_to_mermaid(tree_data):
    mermaid_lines = ["graph BT"]

    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]

        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'

        mermaid_lines.append(f'    {node_id}[{node_label}]')

        if parent_id:
#            mermaid_lines.append(f'    {parent_id} --> {node_id}')
            mermaid_lines.append(f'    {node_id} --> {parent_id}')

        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)

    for root_node in tree_data["nodes"]:
        process_node(root_node)

    return "\n".join(mermaid_lines)


# Extract Mermaid code from text
def extract_mermaid_code(text):
    mermaid_pattern = r'```mermaid\s*(graph[\s\S]*?)```'
    match = re.search(mermaid_pattern, text, re.MULTILINE)

    if not match:
        code_pattern = r'```\s*(graph[\s\S]*?)```'
        match = re.search(code_pattern, text, re.MULTILINE)

    if match:
        code = match.group(1).strip()
    else:
        code = text.strip()

    if not code.startswith('graph '):
        if 'graph ' in code:
            code = code[code.find('graph '):]
        else:
            return text

    code = clean_mermaid_syntax(code)

    return code


# Clean Mermaid syntax to ensure proper formatting
def clean_mermaid_syntax(code):
    code = re.sub(r'(\w+|\]|\)|\})(-->|==>|-.->)(\w+|\[|\(|\{)', r'\1 \2 \3', code)

    def fix_node_brackets(match):
        node_id = match.group(1)
        if not any(c in node_id for c in '[](){}'):
            return f'{node_id}[{node_id}]'
        return node_id
    code = re.sub(r'(?:^|\s)(\w+)(?:\s|$)', fix_node_brackets, code)

    def quote_node_labels(match):
        label = match.group(1)
        if ' ' in label and not label.startswith('"'):
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', quote_node_labels, code)

    def fix_parentheses(match):
        label = match.group(1)
        if '(' in label or ')' in label:
            return f'["{label}"]'
        return f'[{label}]'
    code = re.sub(r'\[(.*?)\]', fix_parentheses, code)

    code = code.replace('\r\n', '\n').strip()

    return code


# Render Mermaid diagram in Streamlit
def mermaid(code: str, height: int = 500) -> None:
    components.html(
        f"""
        <pre class="mermaid" style="height: {height}px;">
            {code}
        </pre>

        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true }});
        </script>
        """,
        height=height,
    )
    

# Generate attack tree using Mistral API
def get_attack_tree(api_key, selected_model, prompt, system_context):
    client = Mistral(api_key=api_key)
    system_prompt = create_attack_tree_prompt(system_context)
    response = client.chat.complete(
        model=selected_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
    )
    try:
        cleaned_response = clean_json_response(response.choices[0].message.content)
        tree_data = json.loads(cleaned_response)
        return tree_data
    except json.JSONDecodeError:
        return extract_mermaid_code(response.choices[0].message.content) # Fallback: try to extract Mermaid code if JSON parsing fails


# Generate DREAD assessment using Mistral API
def get_dread_assessment(api_key, selected_model, prompt):
    client = Mistral(api_key=api_key)

    response = client.chat.complete(
        model=selected_model,
        response_format={"type": "json_object"},
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    try:
        dread_assessment = json.loads(response.choices[0].message.content)
    except json.JSONDecodeError:
        dread_assessment = {}

    return dread_assessment


# Load model attributes from AML file into session state
def load_model_attributes():
    print(st.session_state['aml_file'][:500])
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
    #check_probability_data(aml_data)
    bbn_exposure, last_node = create_bbn_exposure()
    bbn_impact = create_bbn_impact(bbn_exposure)
    #check_bbn_models(bbn_exposure, bbn_impact)

    inference_exposure = VariableElimination(bbn_exposure)
    inference_impact = VariableElimination(bbn_impact)

    start_node = st.session_state['start_node']

    if 'attack_paths' in st.session_state:
        start_node = st.session_state['attack_paths'].split(" --> ")[0]
        #last_node = st.session_state['attack_paths'].split(" --> ")[-1]

    #print ("[*] Start Node:", start_node, "\n[*] Last Node: ",last_node)

    cpd_prob, cpd_impact = compute_bayesian_probabilities(inference_exposure, inference_impact, st.session_state['aml_data'].total_elements, start_node, last_node)

    risk_score = cpd_prob * cpd_impact * 100

    st.session_state['cpd_prob'] = cpd_prob
    st.session_state['cpd_impact'] = cpd_impact
    st.session_state['risk_score'] = risk_score

    print('--------------------------')
    print(datetime.now())
    print('--------------------------')
    print('[+] P(Exposure): {:.4f}%'.format(cpd_prob))
    print('[+] P(Severe Impact): {:.4f}%'.format(cpd_impact))
    print('[+] Risk score: {:.2f}%'.format(risk_score))


# Display risk metrics in sidebar
def display_metrics():
    st.sidebar.metric("Probability of Exposure", value=f"{st.session_state.get('cpd_prob', 0):.4f}")
    st.sidebar.metric("Probability of Severe Impact", value=f"{st.session_state.get('cpd_impact', 0):.4f}")
    st.sidebar.metric("Risk Score", value=f"{st.session_state.get('risk_score', 0):.2f}%")