from flask import Flask, jsonify, render_template, request, send_file, Response
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
import json
import collections
import time
import queue
import ipaddress
import threading

app = Flask(__name__)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

MAX_HISTORY = 1000
packets_history = collections.deque(maxlen=MAX_HISTORY)

stats = {
    "TCP": 0, "UDP": 0, "HTTP": 0, "HTTPS": 0, "DNS": 0, 
    "ICMP": 0, "ARP": 0, "OTHER": 0
}

# Tracking IPs and alerts
ip_traffic_count = collections.defaultdict(int)
tcp_syn_tracker = collections.defaultdict(set)
recent_alerts = collections.deque(maxlen=50)

clients = []

def get_ip_info(ip_str):
    if ip_str == "N/A" or ip_str == "-" or not ip_str:
        return ""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_multicast: return "Multicast"
        if ip.is_private: return "Local"
        if ip.is_loopback: return "Loopback"
        if ip.is_reserved: return "Reserved"
        return "Public"
    except:
        return ""

def process_packet(packet):
    protocol = "OTHER"
    port = "-"
    src = "N/A"
    dst = "N/A"
    info = ""
    alert = None

    length = len(packet)

    if packet.haslayer(ARP):
        protocol = "ARP"
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
        info = "ARP Request" if packet[ARP].op==1 else "ARP Reply"

    elif packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        # TOP IP Tracking
        ip_traffic_count[src] += 1

        if packet.haslayer(ICMP):
            protocol = "ICMP"
            info = f"Type: {packet[ICMP].type} Code: {packet[ICMP].code}"
            
            # RULE: Ping of death / Large ICMP
            if length > 1000:
                alert = f"[Suspicious] Large ICMP Ping ({length}B) from {src}. Possible Ping of Death or Exfiltration."

        elif packet.haslayer(TCP):
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            port = f"{sport} → {dport}"

            if dport == 80 or sport == 80:
                protocol = "HTTP"
            elif dport == 443 or sport == 443:
                protocol = "HTTPS"
            elif dport == 22 or sport == 22:
                protocol = "SSH"
            else:
                protocol = "TCP"
                
            flags = packet[TCP].flags
            info = f"Flags: {flags}"

            # RULE: TCP Port Scanning (Too many distinct SYN packets to different ports)
            # if flags == 2 (SYN) or 'S' in str(flags)
            if 'S' in str(flags) and 'A' not in str(flags):
                tcp_syn_tracker[src].add(dport)
                if len(tcp_syn_tracker[src]) > 15:
                    alert = f"[Alert] Active Port Scan detected by {src}! Scanning > 15 ports."
                    tcp_syn_tracker[src].clear() # Reset to avoid infinite spam

        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
            sport = packet[UDP].sport
            port = f"{sport} → {dport}"

            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                protocol = "DNS"
                try:
                    qname = packet[DNSQR].qname.decode('utf-8').lower()
                    info = f"Query: {qname}"
                    
                    # RULE: Tor / Crypto tracking
                    if any(kw in qname for kw in ["crypto", "mining", "tor", "onion", "hack"]):
                        alert = f"[Suspicious] Blacklisted domain keyword queried: {qname} by {src}"
                except:
                    info = "DNS Query"
            elif dport == 53 or sport == 53:
                protocol = "DNS"
            else:
                protocol = "UDP"

    if protocol == "OTHER" and length < 20:
        return

    data = {
        "id": int(time.time() * 1000),
        "time": time.strftime('%H:%M:%S'),
        "src": src,
        "src_info": get_ip_info(src),
        "dst": dst,
        "dst_info": get_ip_info(dst),
        "protocol": protocol,
        "port": port,
        "length": length,
        "info": info
    }

    if alert:
        data["alert"] = alert
        recent_alerts.appendleft({"time": data["time"], "alert": alert})

    if protocol in stats:
        stats[protocol] += 1
    else:
        stats["OTHER"] += 1

    packets_history.appendleft(data)

    for client_queue in clients:
        try:
            client_queue.put_nowait(data)
        except queue.Full:
            pass

def get_stats_summary():
    top_ips = sorted(ip_traffic_count.items(), key=lambda item: item[1], reverse=True)[:5]
    return {
        "TCP": stats["TCP"],
        "UDP": stats["UDP"],
        "HTTP": stats["HTTP"],
        "HTTPS": stats["HTTPS"],
        "DNS": stats["DNS"],
        "ICMP": stats["ICMP"],
        "ARP": stats["ARP"],
        "OTHER": stats.get("OTHER", 0),
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips]
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stream")
def stream():
    def event_stream():
        q = queue.Queue(maxsize=100)
        clients.append(q)
        try:
            while True:
                data = q.get()
                payload = {
                    "packet": data,
                    "total_packets": sum(stats.values()),
                    "stats": get_stats_summary()
                }
                yield f"data: {json.dumps(payload)}\n\n"
        except GeneratorExit:
            clients.remove(q)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/download")
def download_logs():
    with open("packets.json", "w") as f:
        json.dump(list(packets_history), f, indent=4)
    return send_file("packets.json", as_attachment=True)

@app.route("/api/alerts")
def get_alerts():
    return jsonify(list(recent_alerts))

@app.route("/api/stats")
def get_api_stats():
    return jsonify({
        "total_packets": sum(stats.values()),
        "stats": get_stats_summary(),
        "alerts_count": len(recent_alerts)
    })

def inject_dummy_activity():
    time.sleep(3)
    # Fake Port Scan Alert
    dummy1 = {
        "id": int(time.time() * 1000) + 1,
        "time": time.strftime('%H:%M:%S'),
        "src": "45.33.32.156", "src_info": "Public",
        "dst": "192.168.1.100", "dst_info": "Local",
        "protocol": "TCP", "port": "34521 → 22", "length": 60,
        "info": "Flags: S",
        "alert": "[Alert: SAMPLE] Active Port Scan detected by 45.33.32.156! Scanning > 15 ports."
    }
    
    time.sleep(1)
    
    # Fake Ping of Death Alert
    dummy2 = {
        "id": int(time.time() * 1000) + 2,
        "time": time.strftime('%H:%M:%S'),
        "src": "119.28.1.5", "src_info": "Public",
        "dst": "192.168.1.1", "dst_info": "Local",
        "protocol": "ICMP", "port": "-", "length": 4500,
        "info": "Type: 8 Code: 0",
        "alert": "[Suspicious: SAMPLE] Large ICMP Ping (4500B) from 119.28.1.5. Possible Ping of Death."
    }

    for client_queue in clients:
        try:
            client_queue.put_nowait(dummy1)
            time.sleep(0.5)
            client_queue.put_nowait(dummy2)
        except queue.Full:
            pass

if __name__ == "__main__":
    sniffer = AsyncSniffer(prn=process_packet, store=False)
    sniffer.start()
    
    threading.Thread(target=inject_dummy_activity, daemon=True).start()
    
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True, use_reloader=False)