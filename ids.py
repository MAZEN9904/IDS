#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP
from flask import Flask, render_template_string
from datetime import datetime, timedelta
import smtplib
from datetime import datetime
import threading

sensitive_ports = [21, 22, 23, 80, 443, 3306, 8080]

connection_counter = {}

EMAIL = "mazenmagdy1598@gmail.com"
PASSWORD = "qqcb hevl rsry jhyr"  
TO_EMAIL = "mazenmagdy3578@gmail.com"


app = Flask(__name__)
logs = []


def send_email_alert(ip, port, attack_type):
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL, PASSWORD)
        message = f"""
        Subject: IDS Alert!

        Possible Attack Detected!
        Time: {datetime.now()}
        Source IP: {ip}
        Target Port: {port}
        Attack Type: {attack_type}
        """
        server.sendmail(EMAIL, TO_EMAIL, message)
        server.quit()
    except Exception as e:
        print("Error sending email:", e)


def analyze_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if dst_port in sensitive_ports:
            connection_counter[src_ip] = connection_counter.get(src_ip, 0) + 1
            connection_counter.setdefault(src_ip, []).append(datetime.now())
            recent = [t for t in connection_counter[src_ip] if (datetime.now() - t).total_seconds() < 5]


            if connection_counter[src_ip] > 1000:  
                alert = {
                    "time": str(datetime.now()),
                    "ip": src_ip,
                    "port": dst_port,
                    "attack": "Possible DoS Attack"
                }
                logs.append(alert)
                print(alert)
                send_email_alert(src_ip, dst_port, "DoS Attack")
                if src_ip == "127.0.0.1":
                    return       


def start_sniff():
    sniff(prn=analyze_packet, store=False)

@app.route("/logs.json")
def logs_json():
    return {"logs": logs}


@app.route("/")
def index():
    template = """
    <h2>IDS Alerts</h2>
    <ul id="loglist">
    {% for log in logs %}
        <li>{{ log.time }} | {{ log.ip }} | {{ log.port }} | {{ log.attack }}</li>
    {% endfor %}
    </ul>

    <script>
    setInterval(() => {
        fetch("/logs.json")
        .then(res => res.json())
        .then(data => {
            const ul = document.getElementById("loglist");
            ul.innerHTML = "";
            data.logs.forEach(log => {
                const li = document.createElement("li");
                li.textContent = log.time + " | " + log.ip + " | " + log.port + " | " + log.attack;
                ul.appendChild(li);
            });
        });
    }, 2000); 
    </script>
    """
    return render_template_string(template, logs=logs)


if __name__ == "__main__":
    threading.Thread(target=start_sniff, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
