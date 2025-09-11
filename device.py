import requests
import oqs
import requests

msg = "Patient Heartbeat: 72 BPM"
res = requests.post("http://127.0.0.1:5000/send_data", json={"data": msg})
print(res.json())


ALGO = "Kyber512"

# Step 1: Get server's public key
res = requests.get("http://127.0.0.1:5000/get_public_key")
server_public_key = bytes.fromhex(res.json()["public_key"])
print("✅ Received server's public key")

# Step 2: Encapsulate shared secret
with oqs.KeyEncapsulation(ALGO) as client_kem:
    ciphertext, shared_secret = client_kem.encap_secret(server_public_key)

print("🔑 Shared secret established with server")

# Step 3: Encrypt sensor message
message = "Patient Heartbeat: 72 BPM"
encrypted_message = bytes([a ^ b for a, b in zip(message.encode(), shared_secret)])
print("📡 Sending encrypted data to server...")

# Step 4: Send encrypted data to server
res = requests.post("http://127.0.0.1:5000/send_data", json={
    "ciphertext": ciphertext.hex(),
    "encrypted_message": encrypted_message.hex()
})

print("📩 Server response:", res.json())
