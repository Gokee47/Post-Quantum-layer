from flask import Flask, request, jsonify, render_template
import oqs
import os
from datetime import datetime

app = Flask(__name__)
ALGO = "Kyber512"

# Generate server's keypair ONCE at startup
server_kem = oqs.KeyEncapsulation(ALGO)
server_public_key = server_kem.generate_keypair()

# Store latest decrypted message and metrics
latest_decrypted_message = None
message_count = 0
performance_metrics = {
    'throughput': 2.4,
    'latency': 15,
    'device_count': 4
}

# -------------------- ROUTES --------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html", 
                         decrypted_message=latest_decrypted_message,
                         metrics=performance_metrics,
                         message_count=message_count,
                         now=datetime.now)

@app.route("/api/status")
def status():
    return jsonify({
        "status": "Server running", 
        "quantum_layer": "active",
        "kyber_status": "active"
    })

@app.route("/api/latest_message")
def latest_message():
    return jsonify({"message": latest_decrypted_message or "No message received yet."})

@app.route("/api/metrics")
def get_metrics():
    return jsonify({
        "throughput": performance_metrics['throughput'],
        "latency": performance_metrics['latency'],
        "device_count": performance_metrics['device_count'],
        "message_count": message_count
    })

@app.route("/api/get_public_key")
def get_public_key():
    return jsonify({"public_key": server_public_key.hex()})

@app.route("/api/send_data", methods=["POST"])
def receive_data():
    global latest_decrypted_message, message_count, performance_metrics
    try:
        data = request.get_json()
        ciphertext = bytes.fromhex(data["ciphertext"])
        encrypted_message = bytes.fromhex(data["encrypted_message"])
        device_type = data.get("device_type", "unknown")

        # Use the original server keypair to decapsulate
        shared_secret = server_kem.decap_secret(ciphertext)

        # XOR decryption
        decrypted = bytes([a ^ b for a, b in zip(encrypted_message, shared_secret)])
        decrypted_message = decrypted.decode("utf-8", errors="replace")

        latest_decrypted_message = f"{device_type}: {decrypted_message}"
        message_count += 1
        
        # Update metrics (simulate some variation)
        performance_metrics['throughput'] = round(2.0 + (message_count % 10) / 10, 1)
        performance_metrics['latency'] = 10 + (message_count % 15)
        
        print(f"✅ Received from {device_type}: {decrypted_message}")
        print(f"📊 Total messages: {message_count}")

        return {
            "status": "success", 
            "decrypted": decrypted_message,
            "device_type": device_type
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}, 500

@app.route("/api/simulate_device", methods=["POST"])
def simulate_device():
    global latest_decrypted_message, message_count, performance_metrics
    try:
        data = request.get_json()
        device_type = data.get("device_type", "sensor1")
        
        # Simulate different messages based on device type
        messages = {
            "sensor1": "Temperature: 22.5C, Humidity: 45%",
            "camera1": "Motion detected in Room 101", 
            "lock1": "Door unlocked with PIN code",
            "light1": "Brightness set to 80%"
        }
        
        message = messages.get(device_type, "Test message")
        latest_decrypted_message = f"{device_type}: {message}"
        message_count += 1
        
        # Update metrics
        performance_metrics['throughput'] = round(2.0 + (message_count % 10) / 10, 1)
        performance_metrics['latency'] = 10 + (message_count % 15)
        
        print(f"✅ Simulated {device_type} message: {message}")
        
        return jsonify({
            "status": "success", 
            "message": latest_decrypted_message,
            "device_type": device_type
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000, debug=True)