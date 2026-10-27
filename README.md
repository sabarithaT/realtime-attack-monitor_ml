AI-Driven Cyber Threat Logger

A Python-based cybersecurity application that monitors and analyzes security events using machine learning and rule-based threat detection. The project provides a Flask web dashboard for viewing events, suspicious activity, and threat severity.

Features

Interactive Dashboard: View event counts, alerts, severity levels, and predicted classes.
Threat Detection: Identify simulated DDoS activity, brute-force attempts, SQL injection patterns, and port scans.
Machine Learning: Classify traffic patterns using trained machine-learning models.
Event Logging: Record and review security events.
Severity Classification: Categorize events according to their assigned severity.
Ledger Integrity: Verify the integrity of recorded events using a hash-chain ledger.
Data Import: Support for importing data for analysis.
Live Monitoring: Optional network traffic analysis, depending on configuration.
Notifications and Integrations: Optional email alerts and external logging integrations.

 Technologies Used

- Python 3.12
- Flask
- scikit-learn
- pandas and NumPy
- SQLite
- Scapy
- HTML and CSS
- Machine Learning
- Network Security Monitoring

 Installation and Setup

 Prerequisites

- Python 3.12
- Visual Studio Code or another Python editor

 Steps

1. Download `cyber-threat-logger.zip` from this repository.
2. Extract the ZIP file.
3. Open the extracted `cyber-threat-logger` folder in your terminal.
4. Create a virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   ```

5. Activate the virtual environment:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

6. Install the dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

7. Start the application:

   ```powershell
   python app.py
   ```

8. Open the dashboard in your browser:

   http://127.0.0.1:5000

Keep the terminal open while the application is running.

 Testing Status

The application has been started locally, and simulated events have produced dashboard updates. Further testing is needed to validate model accuracy, event persistence, ledger integrity, live network monitoring, email delivery, and external integrations.

 Responsible Use

Use network monitoring and security testing features only on systems you own or are authorized to assess. Machine-learning predictions and alerts should be verified before being treated as confirmed incidents.

 Future Improvements

- Validate detection accuracy with suitable datasets.
- Test live traffic capture in an authorized lab.
- Improve alert filtering and event analysis.
- Validate notification and external integration features.

 License

No license has been specified for this project yet.
