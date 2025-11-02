# ASTRAL (Architecture-Centric Security Threat & Risk Assessment using LLMs)
### Prototype Tool for LLM-Powered CPS Security Assessment

This Streamlit web application leverages large language models (LLMs) to support real-time cyber-physical system (CPS) decision-making by generating architectural reconstruction / narration, threat models, attack trees, DREAD risk assessments, and AutomationML files based on uploaded architecture diagrams.

---

## Overview

The application provides an interactive platform for security assessment of cyber-physical systems using LLM-powered analysis. Users can upload system architecture diagrams (images), clarify LLM responses (text) and receive comprehensive security assessments including:

- **Architectural Narration**: Automated extraction and understanding of system components and data flows
- **Threat Modeling**: STRIDE-LM methodology-based threat identification and analysis (Spoofing, Tampering, Repudiation, Impersonation, Denial-of-Service, Elevation of Privileges, Lateral Movement)
- **Attack Tree Generation**: Hierarchical visualization of potential attack vectors using Mermaid diagrams
- **Risk Assessment**: DREAD-based risk prioritization (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
- **Bayesian Network Analysis**: Probabilistic modeling of security risks and countermeasures
- **AutomationML Export**: Generation of AutomationML (.aml) files for system representation and analysis

---

## Features

### STRIDE-LM Threat Modeling

The application implements an enhanced STRIDE methodology tailored for cyber-physical systems:
- Automated identification of assets, trust boundaries, and data flows
- LLM-powered threat generation based on system context
- Structured JSON output for integration with security tools

### Mermaid Attack Trees

Hierarchical attack trees visualize:
- Attack goals and sub-goals
- Attack vectors and prerequisites
- AND/OR relationships between attack steps
- Interactive diagrams for security training and documentation

### DREAD Risk Assessment

Quantitative risk scoring system:
- Damage: Potential impact of successful attack
- Reproducibility: Ease of repeating the attack
- Exploitability: Skill level required to exploit
- Affected Users: Scope of impact
- Discoverability: Likelihood of threat discovery

### Bayesian Network Analysis and Countermeasure Simulation

Probabilistic modeling capabilities:
- Causal relationships between threats and vulnerabilities
- Countermeasure effectiveness simulation
- Risk propagation analysis

### Multi-LLM Support

Flexible integration with multiple LLM providers:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Mistral AI
- Easy switching between providers based on availability and cost

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- API keys for at least one LLM provider (OpenAI, Anthropic, or Mistral)

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shaofeihuang/LLM-DS.git
   cd LLM-DS
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API keys**:
   - Add your API keys to Azure Key Vault (default)
   - Otherwise, add your API keys to a `.env` file for local testing:
   ```bash
   # .env file
   MISTRAL_API_KEY=your_mistral_api_key_here
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   OPENAI_API_KEY=your_openai_api_key_here
   ```

4. **Run the application**:
   ```bash
   streamlit run main.py
   ```

5. **Access the application**:
   - Open your browser and navigate to `http://localhost:8501`

---

## Requirements

Key dependencies include:

- **Streamlit** (1.50.0): Web application framework
- **LLM Providers**: OpenAI, Anthropic, MistralAI
- **Bayesian Analysis**: pgmpy, pyro-ppl, torch
- **Security**: azure-keyvault-secrets, azure-identity

See `requirements.txt` for the complete list of dependencies.

---

## Usage Guide

### Step 1: Configure Settings
1. Launch the application using `streamlit run main.py`
2. Select LLM provider and model from pull-down menu
3. Enter your own API key if needed
4. Select CPS system context from pull-down menu. Click the input field and enter your own custom context if needed.

### Step 2: Upload Architecture Diagram
1. Navigate to the upload section in the UI
2. Upload your system architecture diagram or data flow diagram (supports common image formats: PNG, JPG, JPEG)

### Step 3: Generate Architectural Explanation
1. Click the "Generate Architectural Explanation" button
2. The LLM will analyze the diagram and provide a detailed textual explanation of the system components, data flows, and interactions
3. Review the explanation, optionally add further prompts to the LLM, and download in markdown format if needed

### Step 4: Create Threat Model
1. Navigate to the "Threat Model" tab
2. Click "Generate STRIDE-LM Threat Model"
3. The system uses STRIDE-LM methodology to identify potential threats:
   - **S**poofing
   - **T**ampering
   - **R**epudiation
   - **I**nformation Disclosure
   - **D**enial of Service
   - **E**levation of Privilege
   - **L**ateral **M**ovement
4. Review and download the threat model in JSON format if needed.

### Step 5: DREAD Risk Assessment
1. Navigate to the "DREAD Assessment" tab
2. Generate risk assessments for identified threats
3. Review risk scores based on:
   - **D**amage potential
   - **R**eproducibility
   - **E**xploitability
   - **A**ffected users
   - **D**iscoverability
4. Download the assessment results in markdown format if needed.

### Step 6: Generate Attack Tree and Paths
1. Move to the "Attack Tree" tab
2. Click "Generate Attack Tree and Paths"
3. The system generates attack paths, attack tree code that is compatible with Mermaid, and an attack tree diagram preview
4. Download the attack tree code for visualization in Mermaid Live, and download the raw attack tree data in JSON format if needed.

### Step 7: Generate System Model
1. Navigate to the "System Model" tab
2. Click "Generate AutomationML File"
3. The system creates an AutomationML representation of the system. This process may take several minutes depending on the complexity of the system architecture and threat model
4. Check the generated AutomationML file and make sure the file starts with "```xml" on the first line. If not, download to edit then upload the edited file
4. Download the .aml file if needed.

### Step 8: Bayesian Network Analysis
1. Navigate to the "Analysis" tab
2. Optionally change the system installation date if needed
3. Click "Load Model Attributes". Probabilistic model of exposure (successful attack), severe impact, and risk score is computed automatically
4. Edit model attribute values, change "Attacker ID" and "Attack Feasibility (AF) Modifier" values, if needed

### Step 9: Countermeasure Simulation
1. Navigate to the "Countermeasures" tab
2. Change mitigation likelihood values for each vulnerability (i.e. probability that countermeasure(s) will mitigate the vulnerability) to find the most effective combination for reducing risk


---

## Project Structure

```
LLM-DS/
│
├── main.py                 # Main Streamlit application entry point
├── bayesian.py            # Bayesian network analysis and probabilistic modeling
├── prompts.py             # LLM prompt templates for various analysis tasks
├── utils.py               # Utility functions (attack trees, DREAD, parsing, etc.)
├── requirements.txt       # Python package dependencies
├── .env                   # API key configuration (not committed to repo)
├── README.md              # This file
│
└── examples/              # Example files and demonstrations
    ├── Architecture Diagrams/   # Sample system architecture diagrams
    ├── Attack Models/           # Example attack model outputs
    └── AutomationML Files/      # Sample AutomationML files
```

### Main Modules

- **main.py**: Core Streamlit application with multi-tab UI, image upload, LLM integration, and output generation
- **bayesian.py**: Implements Bayesian network construction, probabilistic inference, and countermeasure analysis
- **prompts.py**: Contains prompt engineering functions for architectural explanation, threat modeling, attack tree generation, DREAD assessment, and AutomationML generation
- **utils.py**: Provides utility functions for parsing LLM outputs, generating Mermaid diagrams, calculating risk scores, and formatting data
- **requirements.txt**: Lists all Python dependencies with version specifications
- **.env**: Configuration file for API keys (template provided, users must add their own keys)

---

## Examples

The `examples/` directory contains:

- **Architecture Diagrams**: Sample CPS architecture diagrams to test the application
- **Attack Models**: Example attack models generated by the system
- **AutomationML Files**: Sample AutomationML system models

These examples demonstrate the application's capabilities and serve as references for expected input/output formats.

---

## License

This project is provided as-is for research and educational purposes. Please check with the repository owner for specific license terms.

---

## Support and Contact

For questions, issues, or suggestions:
- Open an issue on GitHub
- Check existing documentation in the `examples/` directory
- Review the code comments for implementation details
