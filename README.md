# 🛡️ PhishGuard AI

### AI-Powered Phishing & Digital Scam Detection Platform

PhishGuard AI is a machine-learning-based cybersecurity platform designed to detect phishing URLs and digital scam/spam messages.

The system combines **Machine Learning, Natural Language Processing (NLP), URL structural analysis, security rules, and explainable risk scoring** to help users identify suspicious digital content before interacting with it.

---

## 🚀 Key Features

- 🔗 **Phishing URL Detection**
- 💬 **Scam / Spam Message Detection**
- 🤖 **Machine Learning-Based Classification**
- 🔍 **URL Structural & Security Analysis**
- 📊 **Explainable Risk Score**
- ⚠️ **Threat Levels: Safe, Low, Medium, High**
- 🌐 **Embedded URL Detection inside Messages**
- 🗂️ **Scan History**
- 📈 **Security Analytics Dashboard**
- 💾 **SQLite Database**
- 🎨 **Professional Web Interface**

---

## 🧠 Technologies Used

| Category | Technology |
|---|---|
| Backend | Python, Flask |
| Machine Learning | Scikit-learn |
| NLP | TF-IDF, Logistic Regression |
| URL Detection | Random Forest |
| Data Processing | Pandas, NumPy |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Model Storage | Joblib |
| Version Control | Git, GitHub |

---

## 🏗️ System Architecture

```text
                    ┌─────────────────────┐
                    │       User          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Flask Web App     │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │                                 │
              ▼                                 ▼
     ┌──────────────────┐             ┌──────────────────┐
     │   URL Scanner    │             │ Message Scanner  │
     └────────┬─────────┘             └────────┬─────────┘
              │                                 │
              ▼                                 ▼
     ┌──────────────────┐             ┌──────────────────┐
     │ Random Forest ML │             │ TF-IDF + Logistic│
     │ URL Classifier   │             │ Regression       │
     └────────┬─────────┘             └────────┬─────────┘
              │                                 │
              └────────────────┬────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Hybrid Risk Engine  │
                    │ + Security Rules    │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Risk Score & Result │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ SQLite Scan History │
                    └─────────────────────┘