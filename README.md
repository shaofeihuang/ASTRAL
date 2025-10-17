# LLM-Powered Real-Time Cyber-Physical System Decision Support

This Streamlit web application leverages large language models (LLMs) to support real-time cyber-physical system (CPS) decision-making by generating architectural explanations, threat models, attack trees, DREAD risk assessments, and AutomationML files based on uploaded architecture diagrams.

---

## Overview

The application provides an interactive platform for security assessment of cyber-physical systems using LLM-powered analysis. Users can upload system architecture diagrams (images) and receive comprehensive security assessments including:

- **Architectural Analysis**: Automated explanation and understanding of system components and data flows
- **Threat Modeling**: STRIDE-LM methodology-based threat identification and analysis
- **Attack Tree Generation**: Hierarchical visualization of potential attack vectors using Mermaid diagrams
- **Risk Assessment**: DREAD-based risk prioritization (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)
- **Bayesian Network Analysis**: Probabilistic modeling of security risks and countermeasures
- **AutomationML Export**: Generation of AutomationML (.aml) files for industrial automation systems

---

## Features

- Upload architecture or data flow diagram (DFD) images for automated analysis
- Generate detailed architectural explanations to improve system understanding
- Create comprehensive threat models using the STRIDE-LM methodology
- Visualize hierarchical attack trees with Mermaid diagrams
- Perform DREAD risk assessments to prioritize risks
- Generate AutomationML (.aml) files following custom specifications and example references
- Download generated outputs (explanations, models, trees, assessments, AML files) for offline use or reporting
- Clean, multi-tab interactive UI guiding through the decision support workflow
- Support for multiple LLM providers (OpenAI, Anthropic, Mistral)
- Bayesian network modeling for probabilistic risk analysis
- JSON-structured outputs for easy integration with other tools

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
   - Copy the `.env` file and add your API keys:
   ```bash
   # .env file
   MISTRAL_API_KEY=your_mistral_api_key_here
   ANTHROPIC_API_KEY=your_anthropic_api_key_here
   # Add OpenAI key if using OpenAI models
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
- **LLM Providers**: openai, anthropic, mistralai
- **Data Science**: pandas, numpy, scipy, scikit-learn
- **Bayesian Analysis**: pgmpy, pyro-ppl, torch
- **Image Processing**: Pillow
- **Security**: azure-keyvault-secrets, azure-identity
- **Visualization**: plotly, matplotlib

See `requirements.txt` for the complete list of dependencies.

---

## Usage Guide

### Step 1: Upload Architecture Diagram
1. Launch the application using `streamlit run main.py`
2. Navigate to the upload section in the UI
3. Upload your system architecture diagram or data flow diagram (supports common image formats: PNG, JPG, JPEG)

### Step 2: Generate Architectural Explanation
1. Click the "Generate Explanation" button
2. The LLM will analyze the diagram and provide a detailed textual explanation of the system components, data flows, and interactions
3. Review the explanation and download if needed

### Step 3: Create Threat Model
1. Navigate to the "Threat Model" tab
2. Click "Generate Threat Model"
3. The system uses STRIDE-LM methodology to identify potential threats:
   - **S**poofing
   - **T**ampering
   - **R**epudiation
   - **I**nformation Disclosure
   - **D**enial of Service
   - **E**levation of Privilege
4. Review and download the threat model in JSON format

### Step 4: Generate Attack Tree
1. Move to the "Attack Tree" tab
2. Click "Generate Attack Tree"
3. The system creates a hierarchical visualization of attack vectors using Mermaid diagrams
4. View the interactive diagram and download for documentation

### Step 5: DREAD Risk Assessment
1. Navigate to the "DREAD Assessment" tab
2. Generate risk assessments for identified threats
3. Review risk scores based on:
   - Damage potential
   - Reproducibility
   - Exploitability
   - Affected users
   - Discoverability
4. Export the assessment results

### Step 6: Bayesian Network Analysis (Optional)
1. Access the Bayesian analysis section
2. Generate probabilistic models of security risks
3. Analyze countermeasure effectiveness
4. View probability distributions and causal relationships

### Step 7: Generate AutomationML Files
1. Navigate to the "AutomationML" tab
2. Click "Generate AML File"
3. The system creates AutomationML files following industrial automation standards
4. Download the .aml file for integration with automation systems

### Output Files

All generated outputs can be downloaded:
- Architectural explanations (TXT/JSON)
- Threat models (JSON)
- Attack trees (Mermaid format, PNG)
- DREAD assessments (JSON)
- Bayesian networks (JSON)
- AutomationML files (.aml)

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
- **Attack Models**: Example threat models and attack trees generated by the system
- **AutomationML Files**: Sample AutomationML outputs for industrial automation integration

These examples demonstrate the application's capabilities and serve as references for expected input/output formats.

---

## Features in Detail

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

### Bayesian Network Analysis

Probabilistic modeling capabilities:
- Causal relationships between threats and vulnerabilities
- Countermeasure effectiveness estimation
- Risk propagation analysis
- Inference using pgmpy and Pyro

### Multi-LLM Support

Flexible integration with multiple LLM providers:
- OpenAI (GPT-4, GPT-3.5)
- Anthropic (Claude)
- Mistral AI
- Easy switching between providers based on availability and cost

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please ensure your code:
- Follows Python PEP 8 style guidelines
- Includes appropriate documentation
- Passes existing tests
- Adds new tests for new features

---

## License

This project is provided as-is for research and educational purposes. Please check with the repository owner for specific license terms.

---

## Acknowledgments

- STRIDE threat modeling methodology by Microsoft
- DREAD risk assessment framework
- AutomationML standard for industrial automation
- Streamlit for the excellent web framework
- OpenAI, Anthropic, and Mistral AI for LLM capabilities
- The open-source community for the various Python libraries used in this project

---

## Support and Contact

For questions, issues, or suggestions:
- Open an issue on GitHub
- Check existing documentation in the `examples/` directory
- Review the code comments for implementation details

---

## Future Development

Planned enhancements:
- Additional LLM provider support
- Enhanced visualization options
- Export to additional security tool formats
- Real-time collaboration features
- Integration with CI/CD pipelines
- Extended Bayesian network capabilities
