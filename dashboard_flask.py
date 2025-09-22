# dashboard_flask.py
from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)
LOG_FILE = 'logs.json'

TEMPLATE = '''
<html>
<head><title>Attack Dashboard</title></head>
<body>
    <h1>AI Attack Detection Dashboard</h1>
    <a href="/refresh">Refresh now</a>
    <table border="1">
        <tr><th>User ID / IP</th><th>Attack Type</th><th>Status</th><th>Timestamp</th></tr>
        {% for log in logs[::-1] %}
        <tr>
            <td>{{ log.user_id }}</td>
            <td>{{ log.attack }}</td>
            <td>{{ log.status }}</td>
            <td>{{ log.timestamp }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
'''


@app.route('/')
def dashboard():
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        except Exception:
            logs = []
    return render_template_string(TEMPLATE, logs=logs)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
