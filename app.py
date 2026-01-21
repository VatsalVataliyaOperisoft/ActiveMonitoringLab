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


app = Flask(__name__)
CORS(app)
init_user_db()
file_lock = threading.Lock()

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

# ---------------- DASHBOARD ----------------
@app.route("/")
def dashboard():
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
<html>
<head>
    <title>SOC Monitoring Dashboard</title>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background:#0b1220; color:#e5e7eb; font-family:Segoe UI; margin:0 }
        header { background:#020617; padding:15px 30px; color:#38bdf8; font-size:22px }
        .container { padding:25px }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px }
        .card { background:#020617; padding:20px; border-radius:12px; border:1px solid #1e293b; margin-bottom:20px }
        h3 { margin-top:0; color:#38bdf8 }
        table { width:100%; border-collapse:collapse }
        th,td { padding:8px; border-bottom:1px solid #1e293b }
        th { color:#93c5fd }
        .online { color:#22c55e }
        .offline { color:#ef4444 }
        .vuln { color:#ef4444; font-weight:bold }
        .rank { color:#facc15; font-weight:bold }
        canvas { max-height:260px !important; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 20px;
        }

    </style>
</head>

<body>
<header>🛡 SOC Monitoring Dashboard</header>

<div class="container">
<div class="card">
    <h3>➕ Create New VM ↔ Web User</h3>

    <form method="POST" action="/create-user">
    <input
        type="text"
        name="username"
        placeholder="Username"
        required
        style="padding:8px;width:40%;border-radius:6px;border:1px solid #1e293b;"
    />

    <input
        type="password"
        name="web_password"
        placeholder="Web App Password"
        required
        style="padding:8px;width:40%;margin-left:10px;
               border-radius:6px;border:1px solid #1e293b;"
    />

    <button
        type="submit"
        style="padding:8px 14px;margin-left:10px;border-radius:6px;
               background:#22c55e;color:#020617;border:none;cursor:pointer;">
        Create User
    </button>
</form>


    <pre id="createUserResult"
         style="margin-top:15px;background:#020617;padding:10px;
                border-radius:8px;display:none;"></pre>
</div>


<div class="card">
    <h3>👥 Provisioned VM ↔ Web Users</h3>
    <table>
        <tr>
            <th>User</th>
            <th>Web Password</th>
            <th>Created</th>
        </tr>
        {% for u in provisioned_users %}
        <tr>
            <td>{{ u["username"] }}</td>
            <td><strong>{{ u["web_password"] }}</strong></td>
            <td>{{ u["created_at"] }}</td>

        </tr>
        {% else %}
        <tr><td colspan="3">No users created</td></tr>
        {% endfor %}
    </table>
</div>

<!-- Linux User Monitoring -->
<div class="grid">
    <div class="card">
        <h3>🟢 Currently Online Users (Linux)</h3>
        <table>
            {% for u in online_users %}
            <tr><td class="online">{{ u }}</td></tr>
            {% else %}
            <tr><td>No users online</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="card">
        <h3>👤 Linux User Status</h3>
        <table>
            <tr><th>User</th><th>Status</th><th>Last Time</th></tr>
            {% for user, info in user_status.items() %}
            <tr>
                <td>{{ user }}</td>
                <td class="{{ 'online' if info.event == 'ONLINE' else 'offline' }}">
                    {{ info.event }}
                </td>
                <td>{{ info.time }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</div>

<div class="grid">
    <!-- Chart (LEFT - 50%) -->
    <div class="card">
        <h3>📊 Vulnerabilities per User</h3>
        <canvas id="vulnChart" style="height:240px;"></canvas>
    </div>

    <!-- Leaderboard (RIGHT - 50%) -->
    <div class="card">
        <h3>🏆 VulnBank Leaderboard</h3>
        <table>
            <tr>
                <th>Rank</th>
                <th>User</th>
                <th>Vulns</th>
            </tr>
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



<!-- VulnBank Details -->
<div class="card">
    <h3>🏦 VulnBank User Vulnerability Details</h3>
    <table>
        <tr>
            <th>User</th>
            <th>Count</th>
            <th>Vulnerabilities</th>
        </tr>
        {% for user, data in leaderboard %}
        <tr>
            <td>{{ user }}</td>
            <td class="vuln">{{ data.count }}</td>
            <td>{{ ", ".join(data.vulns) }}</td>
        </tr>
        {% endfor %}
    </table>
</div>

</div>

<script>
new Chart(document.getElementById('vulnChart'), {
    type: 'bar',
    data: {
        labels: {{ chart_labels | tojson }},
        datasets: [{
            label: 'Vulnerabilities Found',
            data: {{ chart_values | tojson }},
            backgroundColor: '#ef4444'
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { beginAtZero: true }
        }
    }
});
document.getElementById("createUserForm").addEventListener("submit", async function (e) {
    e.preventDefault();

    const username = document.getElementById("newUsername").value.trim();
    const webPassword = document.getElementById("newWebPassword").value;
    const output = document.getElementById("createUserResult");

    if (!username || !webPassword) return;

    output.style.display = "block";
    output.textContent = "Creating user...";

    try {
        const res = await fetch("/api/create-user", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                username: username,
                web_password: webPassword
            })
        });

        const data = await res.json();

        if (data.error) {
            output.textContent = "❌ Error: " + data.error;
        } else {
            output.textContent =
                "✅ User Created\n\n" +
                "Username: " + data.username + "\n" +
                "VM Password (auto-generated): " + data.vm_password + "\n\n" +
                "⚠ Save VM password now. It will not be shown again.";
        }

    } catch (err) {
        output.textContent = "❌ Request failed";
    }
});
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
