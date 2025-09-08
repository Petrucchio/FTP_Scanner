# FTP Network Assessment Tool - Educational Edition

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Educational](https://img.shields.io/badge/purpose-educational-orange.svg)
![Security](https://img.shields.io/badge/security-ethical--first-red.svg)

> **⚠️ IMPORTANT LEGAL NOTICE**: This tool is designed exclusively for educational purposes and authorized security assessments. Unauthorized network scanning may be illegal in your jurisdiction. Always ensure you have explicit permission before testing any systems.

## 🎯 Overview

A comprehensive educational network assessment tool that demonstrates professional Python development practices while teaching network security concepts. This tool performs FTP service discovery and banner analysis using concurrent programming techniques.

### 🏆 Educational Objectives

- Learn network programming with Python sockets
- Understand concurrent programming with ThreadPoolExecutor
- Practice clean code architecture and design patterns
- Explore ethical security assessment methodologies
- Master professional CLI application development

## ✨ Features

### 🔧 Core Functionality
- **Multi-threaded port scanning** with configurable thread pools
- **Banner grabbing** and service identification
- **Educational service pattern matching** 
- **Honeypot detection** for security awareness
- **Professional JSON reporting** with comprehensive metadata

### 🛡️ Security & Ethics
- **Mandatory legal disclaimers** and user confirmation
- **Rate limiting** to respect target systems
- **Educational focus** - no real vulnerability exploitation
- **Responsible disclosure** approach to security research

### 💻 Technical Features
- **Clean architecture** with classes, enums, and dataclasses
- **Robust error handling** with context managers
- **Type hints** for better code maintainability
- **Comprehensive logging** and verbose output options
- **Configurable timeouts** and connection parameters

## 🚀 Installation

### Prerequisites
```bash
# Python 3.7 or higher
python --version
```

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/Petrucchio/FTP_Scanner/tree/main
cd ftp-assessment-tool

# No external dependencies required - uses Python standard library only!
```

## 📖 Usage

### Basic Examples

```bash
# Educational assessment of a single host
python ftp_scanner.py 192.168.1.1

# Specify custom ports
python ftp_scanner.py 192.168.1.1 -p 21,2121,8021

# Verbose educational output
python ftp_scanner.py 192.168.1.1 -v

# Assess multiple hosts from file
python ftp_scanner.py hosts.txt -f

# Save educational report
python ftp_scanner.py 192.168.1.1 -o assessment_report.json
```

### Advanced Usage

```bash
# Custom threading and timeouts
python ftp_scanner.py 192.168.1.1 -T 20 -t 10

# Show educational patterns
python ftp_scanner.py --show-patterns

# Custom service patterns
python ftp_scanner.py 192.168.1.1 -P custom_patterns.json
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --ports` | Specific ports (comma-separated) | Educational default ports |
| `-t, --timeout` | Connection timeout in seconds | 5 |
| `-T, --threads` | Maximum concurrent threads | 10 |
| `-v, --verbose` | Enable verbose educational output | False |
| `-f, --file` | Target is a file with multiple hosts | False |
| `-o, --output` | Save results to JSON file | None |
| `-P, --patterns` | Custom service patterns file | None |
| `--show-patterns` | Display loaded educational patterns | False |

## 📁 Project Structure

```
ftp-assessment-tool/
├── ftp_scanner.py          # Arquivo principal
├── README.md               # Documentação
├── LICENSE                 # Licença MIT
├── examples/               # Exemplos práticos
│   ├── hosts.txt          # Lista de hosts para teste
│   └── custom_patterns.json # Padrões personalizados
└── requirements.txt        # Dependências (vazio - só stdlib)
```

## 🏗️ Architecture

### Core Components

```python
class ServiceInfo(Enum):
    """Service assessment levels for educational purposes"""
    UNKNOWN = "UNKNOWN"
    IDENTIFIED = "IDENTIFIED" 
    OUTDATED = "POTENTIALLY_OUTDATED"
    MODERN = "MODERN_VERSION"

@dataclass
class ServicePattern:
    """Educational service pattern definition"""
    name: str
    pattern: str
    info_level: ServiceInfo
    description: str
    learning_notes: str

class NetworkAssessmentTool:
    """Main educational assessment tool implementation"""
```

### Design Patterns Used
- **Strategy Pattern**: Configurable service pattern matching
- **Context Manager**: Safe socket handling and resource cleanup
- **Factory Pattern**: Dynamic service pattern creation
- **Observer Pattern**: Verbose logging and progress reporting

## 📊 Output Examples

### Console Output
```
🎯 Service #1: 192.168.1.100:21
📋 Banner: 220 ProFTPD 1.3.6 Server ready.
⏱️  Response Time: 0.123s
🔍 Banner Hash: a1b2c3d4

📚 Educational Analysis:
Service: Professional FTP Service
Assessment: MODERN_VERSION
Description: Modern FTP implementation detected
Learning Notes: Recent versions typically include security improvements
```

### JSON Report Structure
```json
{
  "assessment_metadata": {
    "timestamp": "2024-01-15 14:30:25",
    "tool_version": "5.0 Educational",
    "purpose": "Educational network assessment"
  },
  "statistics": {
    "total_services_found": 3,
    "identified_services": 2,
    "possible_honeypots": 0,
    "unique_hosts_assessed": 1
  },
  "educational_findings": [...]
}
```

## 🎓 Educational Value

### Learning Outcomes
- **Network Programming**: Socket creation, connection handling, data transmission
- **Concurrent Programming**: Thread management, futures, synchronization
- **Error Handling**: Exception management, resource cleanup, graceful failures
- **Security Awareness**: Ethical considerations, responsible disclosure, legal compliance
- **Software Design**: Clean architecture, modularity, maintainability

### Concepts Demonstrated
- TCP socket programming
- Multi-threading with thread pools
- Regular expression pattern matching
- JSON data handling and serialization
- Command-line interface design
- Security-first development mindset

## 🔧 Customization

### Custom Service Patterns

Create a JSON file with your educational patterns:

```json
{
  "patterns": [
    {
      "name": "Custom FTP Service",
      "pattern": "MyFTP.*v[0-9]+",
      "info_level": "IDENTIFIED",
      "description": "Custom FTP implementation",
      "learning_notes": "Example of custom pattern matching"
    }
  ]
}
```

### Extending Functionality

```python
# Example: Adding custom assessment logic
class CustomAssessmentTool(NetworkAssessmentTool):
    def custom_analysis(self, banner: str) -> Dict:
        # Your custom educational analysis logic
        pass
```

## 🧪 Testing

```bash
# Test the tool with verbose output
python ftp_scanner.py 127.0.0.1 -v

# Test with sample hosts file
python ftp_scanner.py examples/hosts.txt -f

# Test pattern display
python ftp_scanner.py --show-patterns
```

## 📚 Documentation

- **[Technical Guide](docs/TECHNICAL_GUIDE.md)**: Deep dive into implementation details
- **[Educational Guide](docs/EDUCATIONAL_GUIDE.md)**: Learning objectives and concepts
- **[Legal Notice](docs/LEGAL_NOTICE.md)**: Comprehensive legal information

## ⚖️ Legal & Ethical Use

### ✅ Authorized Use Cases
- Educational learning and skill development
- Testing on your own systems and networks
- Authorized penetration testing with written permission
- Security research in controlled laboratory environments
- Academic coursework and cybersecurity training

### ❌ Prohibited Use Cases
- Unauthorized scanning of third-party systems
- Malicious reconnaissance or attack preparation
- Violation of terms of service or acceptable use policies
- Any illegal activities under local or international law

### 🛡️ Responsible Disclosure
If you discover actual vulnerabilities during authorized testing:
1. Document findings responsibly
2. Follow coordinated disclosure practices
3. Respect vendor response timelines
4. Prioritize user safety over public recognition

## 🤝 Contributing

We welcome educational contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/Petrucchio/FTP_Scanner/tree/main
cd ftp-assessment-tool

# Install development dependencies
pip install -r requirements-dev.txt

# Run pre-commit hooks
pre-commit install
```

### Code Standards
- Follow PEP 8 style guidelines
- Add type hints for all functions
- Include comprehensive docstrings
- Maintain 90%+ test coverage
- Ensure educational value in all features

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### License Summary
- ✅ Use for educational and learning purposes
- ✅ Modify and distribute with attribution
- ✅ Use in academic and training environments
- ⚠️ No warranty provided - use at your own risk
- 📋 Must include license and copyright notice

## 🙏 Acknowledgments

- **Educational Inspiration**: Network security community and ethical hacking resources
- **Technical References**: Python documentation and concurrent programming guides
- **Security Awareness**: Responsible disclosure community and security researchers
- **Code Quality**: Python community best practices and style guides

## 📞 Contact & Support

- **Author**: [Victor farias](https://github.com/Petrucchio)
- **LinkedIn**: [Victor Linkedin](https://www.linkedin.com/in/victorjosecostafarias)
- **Email**: victor.farias.profile@gmail.com


---

<div align="center">

**🎓 Built for Education • 🛡️ Security First • 🐍 Python Excellence**

*Remember: With great code comes great responsibility!*

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![Educational Purpose](https://img.shields.io/badge/Purpose-Educational-brightgreen.svg)](https://github.com/your-username/ftp-assessment-tool)

</div>
