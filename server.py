from flask import Flask, request, jsonify, render_template, send_from_directory
import oqs
import os

app = Flask(__name__)

# Use lattice-based algorithm (Kyber512 for Key Encapsulation)
ALGO = "Kyber512"

# Generate server's keypair
with oqs.KeyEncapsulation(ALGO) as server_kem:
    server_public_key = server_kem.generate_keypair()
    server_secret_key = server_kem.export_secret_key()

# -------------------- ROUTES --------------------

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/info")
def info_page():
    return """
    <h1>🚀 Quantum-Resistant IoT Server</h1>
    <p>Welcome to Digital Dawn Security: Post-Quantum Layer for IoT Data Protection</p>
    <p>Use <a href='/status'>/status</a> to check server status.</p>
    """

@app.route("/status")
def status():
    return jsonify({"status": "Server running", "quantum_layer": "active"})

@app.route("/get_public_key")
def get_public_key():
    return jsonify({"public_key": server_public_key.hex()})

@app.route("/get_public_key_new")
def get_public_key_new():
    with oqs.KeyEncapsulation(ALGO) as kem:
        new_public_key = kem.generate_keypair()[0]
    return jsonify({"public_key": new_public_key.hex()})

@app.route("/send_data", methods=["POST"])
def receive_data():
    try:
        data = request.json
        ciphertext = bytes.fromhex(data["ciphertext"])
        encrypted_message = bytes.fromhex(data["encrypted_message"])

        with oqs.KeyEncapsulation(ALGO, server_secret_key) as server_kem:
            shared_secret = server_kem.decap_secret(ciphertext)

        decrypted = bytes([a ^ b for a, b in zip(encrypted_message, shared_secret)])

        return jsonify({
            "status": "success",
            "decrypted_message": decrypted.decode(errors="ignore")
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/favicon.ico")
def favicon():
    return send_from_directory(os.path.join(app.root_path, "static"), "favicon.ico")

# -------------------- MAIN --------------------

if __name__ == "__main__":
    app.run(port=5000, debug=True)