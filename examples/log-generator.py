import random

templates = [
    "Jan 15 10:23:{sec:02d} server sshd[12345]: Failed password for root from {ip} port {port} ssh2",
    "Jan 15 10:24:{sec:02d} web-server nginx: {ip} - GET /?id=1' UNION SELECT * FROM users-- HTTP/1.1 200",
    "Jan 15 10:25:{sec:02d} server auditd: type=SYSCALL msg=sudo chmod 777 /etc/passwd",
    "Jan 15 10:26:{sec:02d} server syslog: <script>alert('xss')</script> detected in request from {ip}",
    "Jan 15 10:27:{sec:02d} server kernel: iptables DROP IN=eth0 SRC={ip} DPT=22 PROTO=TCP",
    "Jan 15 10:28:{sec:02d} server syslog: Normal user login success for alice from {ip}",
    "Jan 15 10:29:{sec:02d} server syslog: Scheduled backup completed successfully",
    "Jan 15 10:30:{sec:02d} server syslog: Possible ransomware activity detected — high disk I/O on /home",
    "Jan 15 10:31:{sec:02d} server syslog: Service nginx started successfully",
]

def rand_ip():
    return f"{random.randint(10, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

lines = []
for i in range(500):
    t = random.choice(templates)
    line = t.format(ip=rand_ip(), port=random.randint(1024, 65535), sec=i % 60)
    lines.append(line)

with open("demo_logs_500.log", "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print("Wrote demo_logs_500.log with 500 lines")