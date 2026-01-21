from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import json
import os
import threading
import tempfile
import shutil
from user_db import init_user_db, create_user, get_all_users
from user_db import get_user_for_vm   # we’ll add this next
from user_db import mark_vm_created, get_db
from flask_cors import CORS
from flask import session, redirect, url_for


app = Flask(__name__)
CORS(app)
init_user_db()
file_lock = threading.Lock()
app.secret_key = "SOC-LAB-UNIVERSITY-2026"

# ---------------- STORAGE ----------------
LOG_DIR = "logs"
LOG_FILE = f"{LOG_DIR}/activity_logs.json"
user_messages = {}

os.makedirs(LOG_DIR, exist_ok=True)
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)

def read_logs():
    with file_lock:
        try:
            with open(LOG_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            # File was mid-write; fail safely
            return []


MAX_LOGS = 5000
KEEP_LOGS = 2000

def write_log(entry):
    with file_lock:
        logs = []
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
        except Exception:
            logs = []

        logs.append(entry)

        # 🔄 Auto-rotate logs
        if len(logs) > MAX_LOGS:
            logs = logs[-KEEP_LOGS:]

        # ✅ Atomic write
        tmp_fd, tmp_path = tempfile.mkstemp()
        with os.fdopen(tmp_fd, 'w') as tmp_file:
            json.dump(logs, tmp_file, indent=2)

        shutil.move(tmp_path, LOG_FILE)



# ---------------- API ----------------


@app.route("/create-user", methods=["POST"])
def create_user_form():
    username = request.form.get("username")
    web_password = request.form.get("web_password")

    if not username or not web_password:
        return "Username and Web Password required", 400

    try:
        user = create_user(username, web_password)

        # Store VM password temporarily in session-like variable
        return render_template_string("""
        <h2>✅ User Created Successfully</h2>
        <p><strong>Username:</strong> {{ username }}</p>
        <p><strong>Web Password:</strong> {{ web_password }}</p>
        <p><strong>VM Password (SAVE NOW):</strong> {{ vm_password }}</p>
        <p style="color:red;">⚠ This VM password will NOT be shown again</p>
        <a href="/">⬅ Back to Dashboard</a>
        """,
        username=username,
        web_password=web_password,
        vm_password=user["vm_password"]
        )

    except Exception as e:
        return f"Error: {e}", 500

@app.route("/api/web-login", methods=["POST"])
def web_login():
    data = request.json or {}
    username = data.get("username")
    password = data.get("password")

    conn = get_db()
    row = conn.execute(
        "SELECT username, web_password FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    # ❌ intentionally weak auth (LAB)
    if not row:
        return jsonify({"error": "User not found"}), 401

    if row[1] != password:
        return jsonify({"error": "Invalid password"}), 401

    return jsonify({
        "status": "ok",
        "username": username,
        "role": "user"
    })

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Simple LAB admin login (can move to DB later)
        if username == "admin" and password == "admin@123":
            session["logged_in"] = True
            session["user"] = "admin"
            return redirect("/")
        else:
            error = "Invalid credentials"

    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
<title>SOC Lab Login</title>
<style>
body {
    background: linear-gradient(135deg, #020617, #020617);
    font-family: Segoe UI;
    display:flex;
    justify-content:center;
    align-items:center;
    height:100vh;
    color:#e5e7eb;
}
.login-box {
    background:#020617;
    border:1px solid #1e293b;
    padding:35px;
    border-radius:14px;
    width:360px;
    box-shadow:0 10px 40px rgba(0,0,0,0.6);
}
h2 {
    text-align:center;
    color:#38bdf8;
    margin-bottom:25px;
}
input {
    width:100%;
    padding:12px;
    margin:10px 0;
    border-radius:8px;
    border:1px solid #1e293b;
    background:#020617;
    color:white;
}
button {
    width:100%;
    padding:12px;
    background:#38bdf8;
    color:#020617;
    border:none;
    border-radius:8px;
    font-weight:bold;
    cursor:pointer;
}
.error {
    color:#ef4444;
    text-align:center;
    margin-top:10px;
}
.footer {
    margin-top:18px;
    text-align:center;
    font-size:13px;
    color:#94a3b8;
}
</style>
</head>
<body>

<div class="login-box">
    <h2>🛡 SOC LAB LOGIN</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Admin Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}
    <div class="footer">
        University Cyber Security Lab<br>
        Authorized Access Only
    </div>
</div>

</body>
</html>
""", error=error)


@app.route("/api/create-user", methods=["POST"])
def api_create_user():
    data = request.json or {}
    username = data.get("username")
    web_password = data.get("web_password")

    if not username or not web_password:
        return jsonify({"error": "username and web_password required"}), 400

    try:
        user = create_user(username, web_password)
        return jsonify({
            "status": "created",
            "username": user["username"],
            "vm_password": user["vm_password"],   # auto-generated
            "web_password": web_password
        })
    except Exception as e:
            print("CREATE USER ERROR:", e)
            return jsonify({"error": str(e)}), 400

    

@app.route("/api/provision-users", methods=["GET"])
def api_provision_users():
    hostname = request.args.get("host")
    if not hostname:
        return jsonify([])

    # Return users that are NOT yet provisioned on VM
    users = get_user_for_vm(hostname)
    return jsonify(users)


@app.route("/api/vm-created", methods=["POST"])
def vm_created():
    user_id = request.json.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    mark_vm_created(user_id)
    return jsonify({"status": "ok"})


@app.route("/api/report", methods=["POST"])
def receive_report():
    data = request.json or {}
    write_log(data)

    if data.get("source") == "VulnBank-Web":
        event = data.get("event", {})
        user = event.get("user")
        vuln_count = event.get("vuln_count", 0)

        print("[DEBUG] Heartbeat from:", user, "count:", vuln_count)
        # user_messages = {}
        if user and vuln_count >= 2:
            user_messages[user] = {
                "message": "🎉 Congratulations! You have solved this challenge from server.",
                "status": "completed",
                "time": datetime.utcnow().isoformat()
            }
            print("[DEBUG] Message set for user:", user)

    return jsonify({"status": "ok"}), 200


@app.route("/api/user-message", methods=["GET"])
def get_user_message():
    user = request.args.get("user")
    if not user:
        return jsonify({})

    msg = user_messages.get(user)
    if not msg:
        return jsonify({})

    return jsonify(msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
    if not session.get("logged_in"):
        return redirect("/login")
    logs = read_logs()
    provisioned_users = get_all_users()

    # -------- Linux activity logs --------
    latest_per_host = {}
    login_events = []

    for log in logs:
        if log.get("source") == "VulnBank-Web":
            continue

        host = log.get("host")
        if host:
            latest_per_host[host] = log

        for e in log.get("user_events", []):
            login_events.append(e)

    online_users = set()
    for log in latest_per_host.values():
        for u in log.get("online_users", []):
            if isinstance(u, dict):
                online_users.add(u.get("user"))
            else:
                online_users.add(u)

    user_status = {}
    for e in login_events:
        user_status[e["user"]] = {
            "event": e["event"],
            "time": e["time"]
        }

    for user in online_users:
        user_status[user] = {
            "event": "ONLINE",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    # -------- VulnBank logs --------
    vulnbank_logs = [l for l in logs if l.get("source") == "VulnBank-Web"]

    # -------- Build user → vulnerability stats --------
    user_vuln_stats = {}

    for log in vulnbank_logs:
        event = log.get("event", {})
        if event.get("event") == "HEARTBEAT":
            user = event.get("user")
            if not user:
                continue

            user_vuln_stats[user] = {
                "count": event.get("vuln_count", 0),
                "vulns": event.get("vulns", [])
            }

    # -------- Leaderboard (sorted) --------
    leaderboard = sorted(
        user_vuln_stats.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )

    chart_labels = [u for u, _ in leaderboard]
    chart_values = [d["count"] for _, d in leaderboard]

    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>University SOC Dashboard</title>

<style>
:root {
    --bg-main:#020617;
    --bg-panel:#020617;
    --border:#1e293b;
    --primary:#38bdf8;
    --success:#22c55e;
    --danger:#ef4444;
    --warning:#facc15;
    --muted:#94a3b8;
    --text:#e5e7eb;
}

*{box-sizing:border-box}

body{
    margin:0;
    background:var(--bg-main);
    color:var(--text);
    font-family:"Segoe UI",system-ui,sans-serif;
    display:flex;
}

/* ---------- SIDEBAR ---------- */
.sidebar{
    width:260px;
    background:#020617;
    border-right:1px solid var(--border);
    padding:24px 18px;
    height:100vh;
    position:fixed;
}

.sidebar h2{
    color:var(--primary);
    margin-bottom:28px;
}

.sidebar a{
    display:block;
    padding:12px 14px;
    margin-bottom:10px;
    border-radius:12px;
    color:var(--text);
    text-decoration:none;
    cursor:pointer;
    transition:0.2s;
}

.sidebar a:hover,
.sidebar a.active{
    background:#020617;
    border:1px solid var(--border);
}

.sidebar .logout{
    margin-top:40px;
    background:linear-gradient(135deg,#ef4444,#dc2626);
    text-align:center;
    font-weight:600;
}

/* ---------- MAIN ---------- */
.main{
    margin-left:260px;
    width:calc(100% - 260px);
    padding:34px;
}

/* ---------- SECTIONS ---------- */
.section{
    display:none;
    animation:fade 0.3s ease-in;
}

.section.active{
    display:block;
}

@keyframes fade{
    from{opacity:0;transform:translateY(5px)}
    to{opacity:1;transform:none}
}

.section-title{
    font-size:20px;
    color:var(--primary);
    margin-bottom:20px;
    border-left:4px solid var(--primary);
    padding-left:12px;
}

/* ---------- CARDS ---------- */
.card{
    background:linear-gradient(180deg,#020617,#020617);
    border:1px solid var(--border);
    border-radius:18px;
    padding:24px;
    margin-bottom:26px;
    box-shadow:0 12px 30px rgba(0,0,0,0.55);
}

/* ---------- GRID ---------- */
.grid{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(360px,1fr));
    gap:24px;
}

/* ---------- TABLE ---------- */
table{
    width:100%;
    border-collapse:collapse;
}

th,td{
    padding:12px;
    border-bottom:1px solid var(--border);
    font-size:14px;
}

th{
    color:#93c5fd;
    font-weight:600;
    text-transform:uppercase;
    font-size:13px;
}

tr:hover{background:#020617}

/* ---------- STATUS ---------- */
.online{color:var(--success);font-weight:600}
.offline{color:var(--danger);font-weight:600}
.vuln{color:var(--danger);font-weight:700}
.rank{color:var(--warning);font-weight:700}

/* ---------- FORM ---------- */
.form-row{
    display:flex;
    gap:14px;
    flex-wrap:wrap;
}

input{
    flex:1;
    padding:12px;
    border-radius:12px;
    border:1px solid var(--border);
    background:#020617;
    color:white;
}

button{
    padding:12px 20px;
    border-radius:12px;
    background:linear-gradient(135deg,#22c55e,#16a34a);
    color:#020617;
    border:none;
    font-weight:600;
    cursor:pointer;
}

.footer{
    margin-top:50px;
    text-align:center;
    font-size:13px;
    color:var(--muted);
}
</style>
</head>

<body>

<!-- SIDEBAR -->
<div class="sidebar">
    <h2>🛡 SOC LAB</h2>

    <a onclick="showSection('provision')" class="active">User & VM Provisioning</a>
    <a onclick="showSection('linux')">Linux User Monitoring</a>
    <a onclick="showSection('vuln')">Vulnerability Assessment</a>
    <a onclick="showSection('logs')">System Logs</a>

    <a href="/logout" class="logout">🚪 Logout</a>
</div>

<!-- MAIN -->
<div class="main">

<!-- USER + VM -->
<div id="provision" class="section active">
    <div class="section-title">User & VM Provisioning</div>

    <div class="card">
        <form method="POST" action="/create-user">
            <div class="form-row">
                <input name="username" placeholder="Student / User ID" required>
                <input type="password" name="web_password" placeholder="Web Application Password" required>
                <button type="submit">Create User</button>
            </div>
        </form>
    </div>

    <div class="card">
        <table>
            <tr><th>User</th><th>Web Password</th><th>Created</th></tr>
            {% for u in provisioned_users %}
            <tr>
                <td>{{ u["username"] }}</td>
                <td><strong>{{ u["web_password"] }}</strong></td>
                <td>{{ u["created_at"] }}</td>
            </tr>
            {% else %}
            <tr><td colspan="3">No users provisioned</td></tr>
            {% endfor %}
        </table>
    </div>
</div>

<!-- LINUX -->
<div id="linux" class="section">
    <div class="section-title">Linux User Monitoring</div>

    <div class="grid">
        <div class="card">
            <h4>Currently Online</h4>
            <table>
                {% for u in online_users %}
                <tr><td class="online">{{ u }}</td></tr>
                {% else %}
                <tr><td>No active users</td></tr>
                {% endfor %}
            </table>
        </div>

        <div class="card">
            <h4>User Status</h4>
            <table>
                <tr><th>User</th><th>Status</th><th>Last Seen</th></tr>
                {% for user, info in user_status.items() %}
                <tr>
                    <td>{{ user }}</td>
                    <td class="{{ 'online' if info.event == 'ONLINE' else 'offline' }}">{{ info.event }}</td>
                    <td>{{ info.time }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>
</div>

<!-- VULNERABILITY -->
<div id="vuln" class="section">
    <div class="section-title">Vulnerability Assessment & Leaderboard</div>

    <div class="card">
        <table>
            <tr><th>User</th><th>Total</th><th>Identified Vulnerabilities</th></tr>
            {% for user, data in leaderboard %}
            <tr>
                <td>{{ user }}</td>
                <td class="vuln">{{ data.count }}</td>
                <td>{{ ", ".join(data.vulns) }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <table>
            <tr><th>Rank</th><th>User</th><th>Findings</th></tr>
            {% for user, data in leaderboard %}
            <tr>
                <td class="rank">#{{ loop.index }}</td>
                <td>{{ user }}</td>
                <td class="vuln">{{ data.count }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</div>

<!-- LOGS -->
<div id="logs" class="section">
    <div class="section-title">System Logs</div>
    <div class="card">
        Logs collected from Linux monitoring agents and VulnBank services are retained
        for auditing, incident analysis, and academic evaluation.
    </div>
</div>

<div class="footer">
    © 2026 University Cyber Security Laboratory  
    <br>SOC Monitoring & Attack Simulation Platform
</div>

</div>

<script>
function showSection(id){
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById(id).classList.add('active');

    document.querySelectorAll('.sidebar a').forEach(a => a.classList.remove('active'));
    event.target.classList.add('active');
}
</script>

</body>
</html>


"""

    return render_template_string(
        html,
        online_users=sorted(online_users),
        user_status=user_status,
        leaderboard=leaderboard,
        chart_labels=chart_labels,
        chart_values=chart_values,
        provisioned_users=provisioned_users

    )

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
