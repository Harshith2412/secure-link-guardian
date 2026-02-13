# PCI Guardian 

**Automated PCI-DSS Compliance Monitoring & Security Management Platform**

A comprehensive FastAPI-based system for continuous PCI-DSS (Payment Card Industry Data Security Standard) compliance monitoring, vulnerability scanning, and security audit management.




PCI Guardian is an enterprise grade compliance monitoring platform designed to help organizations maintain continuous PCI-DSS compliance. It automates vulnerability scanning, compliance checking, audit logging, and security alerting across your payment processing infrastructure.


- **Continuous Compliance**: Automated daily scans and checks ensure ongoing adherence to PCI-DSS requirements
- **Comprehensive Coverage**: Monitors all 12 PCI-DSS requirement categories
- **Audit-Ready**: Maintains detailed audit logs and generates compliance reports
- **Multi-Tenant**: Supports multiple organizations with isolated data and customized policies
- **Real-Time Alerts**: Immediate notification of security events and compliance violations
- **Developer-Friendly**: RESTful API with comprehensive documentation


## Features

### Compliance Management
- **12 PCI-DSS Requirements Tracking** - Complete coverage of all requirements
- **Automated Compliance Checks** - Scheduled validation of security controls
- **Compliance Reporting** - Generate audit-ready reports in multiple formats
- **Requirement Mapping** - Link vulnerabilities to specific PCI-DSS requirements
- **Evidence Management** - Store and organize compliance evidence

### Security Scanning
- **Vulnerability Scanning** - Automated network and application vulnerability detection
- **Code Analysis** - Static code analysis using Bandit and Semgrep
- **Dependency Scanning** - Identify vulnerable dependencies with Safety
- **Network Scanning** - Port scanning and service detection with Nmap
- **Penetration Testing** - Automated penetration test scheduling and tracking

### Access Control & Authentication
- **Multi-Factor Authentication (MFA)** - Optional 2FA for enhanced security
- **Role-Based Access Control (RBAC)** - Granular permission management
- **Account Lockout** - Automatic lockout after failed login attempts
- **Password Policy Enforcement** - Configurable complexity requirements
- **Session Management** - Secure session handling with timeouts

### Audit & Monitoring
- **Comprehensive Audit Logs** - Track all security-relevant events
- **Real-Time Monitoring** - Prometheus metrics and Grafana dashboards
- **Security Alerts** - Multi-channel notifications 
- **Event Correlation** - Identify patterns in security events
- **Log Retention** - 90-day default retention with configurable periods

### System Management
- **Multi-Tenant Architecture** - Manage multiple organizations
- **System Inventory** - Track all systems processing cardholder data
- **Configuration Baselines** - Define and enforce security configurations
- **Asset Classification** - Identify systems storing/processing payment data
- **Change Tracking** - Monitor configuration changes over time


### Technology Stack

**Backend Framework:**
- FastAPI 0.109 - High-performance async web framework
- Uvicorn - ASGI server with WebSocket support
- Pydantic - Data validation and settings management

**Database:**
- PostgreSQL 16 - Primary data store with ACID compliance
- SQLAlchemy 2.0 - Async ORM with migration support
- Alembic - Database schema migrations

**Caching & Queue:**
- Redis 7 - Session storage, caching, and message broker
- Celery - Distributed task queue for background jobs
- Flower - Celery monitoring and management

**Security Tools:**
- Bandit - Python code security analysis
- Safety - Dependency vulnerability scanning
- Semgrep - Pattern-based static analysis
- python-nmap - Network port scanning

**Monitoring:**
- Prometheus - Metrics collection and alerting
- Grafana - Visualization and dashboards
- python-json-logger - Structured logging

**Notifications:**
- SendGrid - Email notifications
- Slack SDK - Slack channel alerts

---

## PCI-DSS Requirements Coverage

PCI Guardian provides automated monitoring and enforcement for all 12 PCI-DSS v4.0 requirements:

| Req | Description | Coverage |
|-----|-------------|----------|
| **1** | Install and maintain network security controls | Network scanning, firewall rule validation |
| **2** | Apply secure configurations to all system components | Configuration baseline enforcement, change detection |
| **3** | Protect stored account data | Encryption validation, data classification |
| **4** | Protect cardholder data with strong cryptography | TLS/SSL validation, cipher suite checking |
| **5** | Protect all systems from malicious software | Malware detection, dependency scanning |
| **6** | Develop and maintain secure systems and software | Code analysis, vulnerability scanning, patch tracking |
| **7** | Restrict access by business need to know | RBAC enforcement, access reviews |
| **8** | Identify users and authenticate access | MFA, password policy, session management |
| **9** | Restrict physical access to cardholder data | Physical security audit checklist |
| **10** | Log and monitor all access to system components | Comprehensive audit logging, event correlation |
| **11** | Test security of systems and networks regularly | Automated scanning, penetration test tracking |
| **12** | Support information security with policies | Policy management, evidence collection |


## Security Features

### Authentication & Authorization

**Multi-Factor Authentication (MFA)**
- TOTP-based 2FA support
- QR code generation for easy setup
- Recovery codes for account access

**Password Security**
- Bcrypt hashing (14 rounds)
- Password complexity requirements
- Password history tracking (prevent reuse)
- Automatic password expiration (90 days)

**Session Management**
- JWT tokens with short expiration (30 minutes)
- Refresh token rotation
- Automatic logout on inactivity (15 minutes)
- Concurrent session limiting

**Account Protection**
- Account lockout after 6 failed attempts
- 30-minute lockout duration
- IP-based rate limiting
- Suspicious activity detection

### Data Protection

**Encryption at Rest**
- Database encryption (PostgreSQL TDE)
- Fernet encryption for sensitive fields
- Key rotation support

**Encryption in Transit**
- TLS 1.3 enforcement
- Strong cipher suites only
- Certificate validation

**Data Masking**
- Automatic PAN masking in logs
- Sensitive data redaction in API responses

### Network Security

**Rate Limiting**
- Per-IP request limiting (60 req/min default)
- Per-user API limits
- Configurable thresholds

**CORS Protection**
- Whitelist-based origin control
- Credential validation

**Security Headers**
- HSTS enabled
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options



**Important Disclaimer**: PCI Guardian is a compliance monitoring tool and does not guarantee PCI-DSS compliance. Organizations must still undergo official PCI-DSS assessment by a Qualified Security Assessor (QSA). This tool assists in maintaining compliance but does not replace professional security audits.

**Security Notice**: This is a security-critical application. Always follow security best practices, keep dependencies updated, and conduct regular security audits. 

Harshith Madhavaram