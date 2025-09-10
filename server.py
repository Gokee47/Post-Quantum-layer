from flask import Flask, request, jsonify
import oqs

app = Flask(__name__)

# Use lattice-based algorithm (Kyber512 for Key Encapsulation)
ALGO = "Kyber512"

# Generate server's keypair
with oqs.KeyEncapsulation(ALGO) as server_kem:
    server_public_key = server_kem.generate_keypair()
    server_secret_key = server_kem.export_secret_key()


@app.route("/get_public_key", methods=["GET"])
def get_public_key():
    """
    IoT device requests server's public key.
    """
    return jsonify({"public_key": server_public_key.hex()})


@app.route("/send_data", methods=["POST"])
def receive_data():
    """
    IoT device sends ciphertext + encrypted data.
    Server decapsulates shared secret and decrypts message.
    """
    try:
        data = request.json
        ciphertext = bytes.fromhex(data["ciphertext"])
        encrypted_message = bytes.fromhex(data["encrypted_message"])

        # Recreate server KEM with secret key to decap
        with oqs.KeyEncapsulation(ALGO, server_secret_key) as server_kem:
            shared_secret = server_kem.decap_secret(ciphertext)

        # Simple XOR decryption with shared secret
        decrypted = bytes([a ^ b for a, b in zip(encrypted_message, shared_secret)])

        return jsonify({
            "status": "success",
            "decrypted_message": decrypted.decode(errors="ignore")
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


if __name__ == "__main__":
    print("🚀 Quantum-Resistant IoT Server running on http://127.0.0.1:5000")
    app.run(port=5000)

