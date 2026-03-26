# Framework VulnAnalyzer

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 Description

VulnAnalyzer Framework is a vulnerability analysis tool that integrates Caldera to perform automated security assessments. It enables efficient identification and analysis of vulnerabilities in systems and networks.

## ✨ Features

🔍 Automated vulnerability analysis
🔗 Integration with Caldera for security operations
🛡️ Scanning with Nmap
📊 Detailed report generation (HTML, JSON)
🌐 Web interface with dashboard and reports viewer
🔌 REST API for integration with other tools
💾 SQLite database for persistent storage
🐍 Developed in Python
🔧 Flexible configuration using environment variables

## 🚀  Installation

### Prerequisites

- Python 3.10 or higher
- Nmap (for network scanning)
- Access to a Caldera server

### Installation Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/sentryuc/vulnanalyzer.git
cd vulnanalyzer
```

#### 2. Create a Virtual Environment

It is recommended to use a virtual environment to isolate project dependencies from the system environment.

```bash
# Create the virtual environment
python -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

#### 3. Configure Tools and Install requirements.txt

Run the setup script to prepare the Caldera environment:

```bash
chmod +x setup.sh
./setup.sh
```

#### 4. Install Nmap (if not available)

If the tool is run from a server without Nmap installed:

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install nmap -y

# Fedora/CentOS/RHEL
sudo dnf install nmap -y

# Arch/Manjaro
sudo pacman -S nmap

# macOS (with Homebrew)
brew install nmap
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```bash
# Caldera Configuration
CALDERA_BASE_URL=http://your-caldera-server:8888
CALDERA_API_KEY=your-caldera-api-key

# General Configuration
LOG_LEVEL=INFO
OUTPUT_DIR=./reports
```

### Obtaining the Caldera API Key

1. To access Caldera through the Docker container:

```bash
docker exec -it caldera-server /bin/bash
```

1. Retrieve the login credentials (Caldera generates a new API key and password at each startup):

```bash
cat conf/local.yml
```

1. Use the startup credentials depending on whether you want to work with the `red` or `blue` agent.
4.Copy the API key into the `.env` file.

## 📁 Project Structure

```
vulnanalyzer/
├── api/                  # FastAPI application
│   ├── routers/          # API endpoints
│   ├── models.py         # Database models
│   ├── schemas.py        # Pydantic schemas
│   └── database.py       # SQLite configuration
├── config/               # Application settings
├── core/                 # Core functionality
│   ├── scanner.py        # Vulnerability scanner
│   ├── discover.py       # Host discovery
│   ├── exploiter.py      # Exploit execution
│   └── caldera_client.py # Caldera integration
├── docs/                 # Documentation
├── modules/              # Fingerprints and modules
├── reports/              # Report generation
├── services/             # Business logic services
├── web/                  # Web interface
│   └── templates/        # HTML templates
├── main.py               # CLI entry point
├── requirements.txt
└── setup.sh
```

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## 🔗 Useful Links

- [Caldera Documentation](https://caldera.readthedocs.io/)
- [Nmap Guide](https://nmap.org/docs.html)

## 📊 Project Status

- ✅ Basic installation and configuration
- ✅ Caldera integration
- ✅ Nmap integration
- ✅ Report generation (HTML, JSON)
- ✅ Web interface with dashboard
- ✅ REST API
- ✅ SQLite database for storage

---

## 📚 Documentation

- [Manual de Uso](./docs/01_usage.md) - Guía básica de uso de CLI
- [Interfaz Web y API](./docs/02_web_interface.md) - Guía completa de la interfaz web y API REST

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# CLI Usage
python main.py scan 192.168.1.10 --type full

# Start Web Interface
python main.py web

# Access at http://localhost:8000/web/dashboard
```

---

**Note**: This project is under active development. Features may change without prior notice.
