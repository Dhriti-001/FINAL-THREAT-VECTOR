# ⚡ Threat Vector &mdash; Cybersecurity Awareness & Defensive Training SOC

> **A Beginner-Friendly, 100% Local Cybersecurity Web Application for College Presentations & Vivas**  
> Built with **Python (Flask)**, **SQLite**, **Scikit-learn (Machine Learning)**, and a **Professional Dark-Mode SOC Theme**.

---

## 📌 Project Overview
**Threat Vector** is a cybersecurity training and incident response platform designed to simulate the day-to-day workflow of a Security Operations Center (SOC) Tier-1/Tier-2 analyst. 

The application is architected as **one single integrated Flask app** running locally on `http://127.0.0.1:5000/`. It features **zero external cloud dependencies**, **no Docker**, **no React**, and **no complex setup**.

---

## 🏗️ Technology Stack

| Component | Technology | Rationale for College Viva |
| :--- | :--- | :--- |
| **Backend** | Python 3.12 + Flask 3.1 | Lightweight, Pythonic micro-framework; clean routing and session management. |
| **Database** | SQLite 3 (`database.db`) | Serverless, relational ACID database; zero configuration, uses pure SQL queries. |
| **Machine Learning** | Scikit-learn (`model.pkl`) | TF-IDF Vectorization + Logistic Regression classifier with probability calibration. |
| **Multi-Modal Parsing** | `pypdf`, `Pillow`, `hashlib` | Automatic extraction of text from PDF documents, images (PNG, JPG), and SHA-256 cryptographic hashing. |
| **Frontend** | Semantic HTML5, CSS3, Vanilla JS | Modern SOC dark theme (Electric Cyan, Cyber Purple, Emerald, Crimson). No bloated NPM dependencies. |
| **Testing** | Python `unittest` (`test_app.py`) | Automated verification of all 8 core system flows. |

---

## 📂 Project Directory Structure

```text
skills/
│
├── app.py                  # Main Flask application and route handlers
├── database.py             # SQLite schema, seed data, and query helper functions
├── train_model.py          # Scikit-learn TF-IDF + Logistic Regression training script
├── test_app.py             # Automated unit test suite (8 tests)
├── database.db             # Local SQLite database (auto-generated on launch)
├── model.pkl               # Serialized ML threat classifier pipeline
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Unified navigation bar, user HUD, flash alerts, and footer
│   ├── login.html          # Clean authentication entry point (Sign In & Register)
│   ├── index.html          # Main SOC Dashboard (metrics, launchpad, audit log)
│   ├── drill.html          # Interactive Drill Runner (email simulator, indicator checklist)
│   ├── feedback.html       # Instant explainability, MITRE ATT&CK mapping, "Next Drill"
│   ├── inspector.html      # AI Threat Inspector (Multi-modal uploads & Professional Threat Report)
│   ├── ctf.html            # CTF Tactical Range (log forensics, web shells, ciphers)
│   ├── war_room.html       # Incident Response War Room (multi-phase crisis containment)
│   ├── leaderboard.html    # Defense Leaderboard (peer ranking, dynamic accuracy, tier medals)
│   └── profile.html        # Analytics & Risk Profile (weakness diagnosis & certificate)
│
├── static/
│   └── style.css           # Custom SOC dark-mode theme stylesheet (v2.5 High-Contrast)
│
└── data/
    └── scenarios.csv       # 28 realistic simulation scenarios (Phishing, OTP, BEC, etc.)
```

---

## 🚀 How to Run the Project Locally

### 1. Requirements
Ensure Python 3.10+ is installed on your machine. Install the lightweight dependencies:
```bash
pip install flask scikit-learn pypdf pillow
```

### 2. Launch the Application
Run the Flask server:
```bash
python app.py
```
*(On Windows systems where `python` points to Microsoft Store stub, use `& "C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe" app.py` or `py app.py`)*

### 3. Open in Browser
Visit the single integrated link:
```text
http://127.0.0.1:5000/
```

---

## 🧭 Single-Link Application Flow

```mermaid
flowchart TD
    A["http://127.0.0.1:5000/"] --> B{"Is User Authenticated?"}
    B -- No --> C["/login (Sign In / Register)"]
    B -- Yes --> D["/dashboard (Main SOC Command Center)"]
    
    C -- Success --> D
    
    D --> E1["🎯 1. Simulation Drills (/drills & /drills/next)"]
    D --> E2["🔍 2. AI Threat Inspector (/inspector)"]
    D --> E3["🚩 3. CTF Tactical Range (/ctf)"]
    D --> E4["🚨 4. Incident War Room (/war-room)"]
    D --> E5["🏆 5. Defense Leaderboard (/leaderboard)"]
    D --> E6["📈 6. Threat Analytics (/profile)"]
```

---

## 🎯 The Six Core Modules Explained

### 1. Simulation Drills (Continuous Training Engine)
- **Extensive Dataset:** 28 scenarios covering Phishing, Bank SMS OTP scams, CEO Gift Card BEC fraud, QR-code Quishing, Tech Support alerts, and Legitimate authenticated emails.
- **Continuous Flow Engine:** When clicking **"Next Drill"**, the system dynamically queries unanswered drills or seamlessly cycles through scenario IDs. Drills **never run out or crash abruptly**.
- **Interactive Runner:** Displays simulated email client headers (From, To, Subject, SPF/DKIM verification status), full formatted body, indicator selection checkboxes, and Safe/Malicious buttons.
- **Instant Explainable Feedback:** Detailed analysis of correctly identified indicators, technical threat breakdown, and MITRE ATT&CK mapping.

### 2. Upgraded Multi-Modal AI Threat Inspector
- **Multi-Modal Ingestion:** Supports pasting raw text/URLs OR uploading files (PDF, TXT, LOG, EML, PNG, JPG).
- **Automated Text Extraction:** Uses `pypdf` to parse PDF documents, reads plaintext telemetries, and extracts embedded string payloads from image headers.
- **Cryptographic Hash Verification:** Automatically calculates SHA-256 checksums and file sizes for forensic auditing.
- **Automated Professional Threat Report:**
  - One-click **"Generate Professional Threat Report"** button with print/PDF export capability.
  - **Executive Summary & Verdict:** Clear Malicious vs. Safe classification with probability confidence meter.
  - **Structured IoCs:** Separates Network IoCs (domains, URLs, IPs), Host IoCs (SHA-256 hash, file size), and Behavioral Markers (urgency triggers, credential solicitations).
  - **Attack Vector & MITRE ATT&CK Matrix:** Explicit mapping to MITRE techniques (`T1566.001`, `T1566.002`, `T1078`).
  - **Step-by-Step Professional Analyst Workflow (Career Guide):** Educational breakdown of the 5-phase SOC incident handling methodology (Ingestion & Triage, Static Analysis, Machine Learning NLP, Threat Intel Enrichment, and Remediation).

### 3. CTF Tactical Range (Capture The Flag)
6 hands-on tactical puzzles:
1. **SSH Brute Force Intrusion Detection:** Inspect `/var/log/auth.log` to identify attacking IP and breached user account (`flag{192.168.1.105_sysadmin}`).
2. **Obfuscated Web Shell Backdoor:** De-obfuscate an uploaded PHP script to discover the hidden authorization token (`flag{c99_backdoor_auth_token_9918}`).
3. **Intercepted C2 Cipher (ROT13):** Decrypt a Caesar-shifted threat actor beacon (`flag{rot13_challenge_decoded_success}`).
4. **PowerShell Base64 Forensics:** Decode an encoded Task Scheduler payload to reveal the C2 callback URL (`flag{http://evil-c2-listener.darknet/payload.ps1}`).
5. **SQL Injection Detective:** Review Apache access logs with `UNION SELECT` syntax to find target database table (`flag{admin_credentials}`).
6. **Ransomware Note Forensics:** Inspect LockBit ransom text to extract victim identifier (`flag{victim_id_882910_lockbit_recovered}`).

### 4. Incident Response War Room
- Simulates high-stakes emergency incident response under simulated time pressure.
- Scenarios: **Ransomware Outbreak on Domain Controller**, **Distributed Credential Stuffing**, **Executive Spear-Phishing Exfiltration**.
- Guides the trainee through 4 NIST/SANS incident phases:
  - **Phase 1: Detection & Triage**
  - **Phase 2: Containment**
  - **Phase 3: Eradication**
  - **Phase 4: Recovery & Post-Mortem**

### 5. Cybersecurity Defense Leaderboard
- Real-time ranking ladder benchmarking active trainees against peer SOC analysts.
- Dynamically reflects live trainee scores, drills completed, CTF flags captured, and computed **Accuracy Rates** directly from SQLite.
- Displays Gold, Silver, and Bronze rank medals and gamified tier badges (*Security Cadet*, *SOC Analyst*, *Threat Hunter*, *CISO Defender*).

### 6. Analytics & Personal Risk Profile
- Diagnostic threat readiness scorecard (Overall Readiness Index 0-100).
- Category-wise proficiency bars across all 7 attack vectors.
- **Automated SOC Weakness Diagnosis:** Detects the trainee's weakest category (e.g. *"High Susceptibility to Urgency Vectors"*) and provides specific behavioral remediation tips.
- Displays a formal **Certificate of Defense Readiness** suitable for export or printing.

---

## 🧪 Automated Testing
Run the automated test suite to verify all endpoints and features:
```bash
python test_app.py
```
*Output: `Ran 8 tests in 0.8s ... OK`*

---

## 🎓 College Viva Preparation
Read **`VIVA_GUIDE.md`** for 15+ comprehensive questions and answers frequently asked by external college examiners, including mathematical derivations of TF-IDF and Logistic Regression, relational schema design, and cybersecurity concepts!
