import re
import streamlit.components.v1 as components
import xml.etree.ElementTree as ET

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


def at_json_to_markdown(arch_explanation, threat_model):
    markdown_output = "## Architecture Explanation\n\n"
    
    markdown_output += arch_explanation + "\n\n"
    
    markdown_output += "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Threat Type | Scenario | Potential Impact |\n"
    markdown_output += "|-------------|----------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Threat Type']} | {threat['Scenario']} | {threat['Potential Impact']} |\n"
    
    return markdown_output


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


def clean_aml_content(aml_content):
    aml_content = aml_content.strip()
    if aml_content.startswith("```xml"):
        aml_content = aml_content[len("```xml"):].strip()
    if aml_content.endswith("```"):
        aml_content = aml_content[:-len("```")].strip()
    return aml_content


def extract_attributes_from_aml(aml_content):
    ns = {'caex': 'http://www.dke.de/CAEX'}
    root = ET.fromstring(aml_content)

    def parse_attribute(attr):
        attr_dict = {}
        name = attr.attrib.get('Name', '')
        value_elem = attr.find('caex:Value', ns)
        if value_elem is not None:
            attr_dict[name] = value_elem.text
        else:
            nested_attrs = attr.findall('caex:Attribute', ns)
            for nested_attr in nested_attrs:
                nested_parsed = parse_attribute(nested_attr)
                for k, v in nested_parsed.items():
                    attr_dict[f"{name}.{k}"] = v
        return attr_dict

    def extract_elements_starting_with(root, prefix, ns):
        all_nodes = root.findall(".//caex:InternalElement", ns)
        filtered_nodes = [node for node in all_nodes if node.attrib.get('RefBaseSystemUnitPath', '').startswith(prefix)]
        items = []
        for node in filtered_nodes:
            data = {
                'Name': node.attrib.get('Name', ''),
                'ID': node.attrib.get('ID', '')
            }

            for attr in node.findall('caex:Attribute', ns):
                parsed_attr = parse_attribute(attr)
                data.update(parsed_attr)

            items.append(data)
        return items

    def extract_elements(ref_path):
        nodes = root.findall(f".//caex:InternalElement[@RefBaseSystemUnitPath='{ref_path}']", ns)
        items = []
        for node in nodes:
            data = {
                'Name': node.attrib.get('Name', ''),
                'ID': node.attrib.get('ID', '')
            }

            for attr in node.findall('caex:Attribute', ns):
                parsed_attr = parse_attribute(attr)
                data.update(parsed_attr)

            items.append(data)
        return items

    assets = extract_elements_starting_with(root, 'AssetOfICS', ns)
    vulnerabilities = extract_elements('VulnerabilityforSystem/Vulnerability')
    hazards = extract_elements('HazardforSystem/Hazard')

    return assets, vulnerabilities, hazards



def update_aml_from_attributes(aml_content, attr_sets):
    ns = {'caex': 'http://www.dke.de/CAEX'}
    ET.register_namespace('', 'http://www.dke.de/CAEX')
    root = ET.fromstring(aml_content)

    def update_attribute_recursive(attr_node, updated_attrs, parent_key=''):
        # Recursively update nested <Attribute> elements
        #print("attr_node:", attr_node, "updated_attrs:", updated_attrs, "parent_key", parent_key)
        for child in attr_node.findall('caex:Attribute', ns):
            attr_name = child.attrib.get('Name', '')
            if attr_name in updated_attrs:
                value_node = child.find('caex:Value', ns)
                if value_node is None:
                    value_node = ET.SubElement(child, f"{{{ns['caex']}}}Value")
                #old_val = value_node.text
                value_node.text = str(updated_attrs[attr_name])
                #print(f"Updated '{attr_name}': '{old_val}' -> '{value_node.text}'")
            # Recursive descent for deeper nested attributes
            update_attribute_recursive(child, updated_attrs, attr_name)

    def update_internal_element(node, updated_attrs):
        #print("------------------\n")
        #print("node:", node)
        #print("------------------\n")
        #print("attr", updated_attrs.items())
        #print("------------------\n")

        for key, val in updated_attrs.items():
            if key in ['ID', 'Name']:
                continue
            if '.' in key:
                continue
            attr_elem = None
            for a in elem.findall('caex:Attribute', ns):
                if a.attrib.get('Name') == key:
                    attr_elem = a
                    break
                if attr_elem is not None:
                    value_node = attr_elem.find('caex:Value', ns)
                    if value_node is None:
                        value_node = ET.SubElement(attr_elem, f"{{{ns['caex']}}}Value")
                    #old_val = value_node.text
                    value_node.text = str(val)
                    #print(f"Updated '{key}': '{old_val}' -> '{value_node.text}'")
                #else:
                    #print(f"Attribute '{key}' not found in element '{elem.attrib.get('Name')}'")

        # Now handle nested attribute updates - e.g. AutomationEquipments.Vendor
        for attr in node.findall('caex:Attribute', ns):
            parent_name = attr.attrib.get('Name')
            nested_keys = {k[len(parent_name)+1:]: v for k, v in updated_attrs.items()
                           if k.startswith(parent_name + '.')}
            if nested_keys:
                update_attribute_recursive(attr, nested_keys, parent_name)

    # Update assets
    for updated_asset in attr_sets.get('assets', []):
        id_val = updated_asset.get('ID')
        if not id_val:
            #print("Skipped asset with missing ID")
            continue
        elem = root.find(f".//caex:InternalElement[@ID='{id_val}']", ns)
        if elem is not None:
            update_internal_element(elem, updated_asset)
        #else:
            #print(f"Asset element with ID='{id_val}' not found")

    # Update vulnerabilities
    for updated_vuln in attr_sets.get('vulnerabilities', []):
        id_val = updated_vuln.get('ID')
        if not id_val:
            #print("Skipped vulnerability with missing ID")
            continue
        elem = root.find(f".//caex:InternalElement[@ID='{id_val}']", ns)
        if elem is not None:
            update_internal_element(elem, updated_vuln)
        #else:
            #print(f"Vulnerability element with ID='{id_val}' not found")

    # Update hazards
    for updated_hazard in attr_sets.get('hazards', []):
        id_val = updated_hazard.get('ID')
        if not id_val:
            #print("Skipped hazard with missing ID")
            continue
        elem = root.find(f".//caex:InternalElement[@ID='{id_val}']", ns)
        if elem is not None:
            update_internal_element(elem, updated_hazard)
        #else:
            #print(f"Hazard element with ID='{id_val}' not found")

    return ET.tostring(root, encoding='utf-8').decode('utf-8')
