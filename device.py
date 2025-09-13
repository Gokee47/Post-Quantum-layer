import requests
import oqs
import sys

ALGO = "Kyber512"

# Different messages for different devices
device_messages = {
    "sensor1": "Temperature: 22.5C, Humidity: 45%",
    "camera1": "Security Alert: Motion detected in Room 101",
    "lock1": "Access Log: Door unlocked with PIN code",
    "light1": "Lighting Update: Brightness set to 80%"
}

def send_encrypted_message(device_type):
    message = device_messages.get(device_type, "Test message")
    
    try:
        # Step 1: Check if server is running
        print("🔍 Checking server status...")
        res = requests.get("http://127.0.0.1:5000/api/status")
        if res.status_code != 200:
            print("❌ Server is not responding properly")
            return
        else:
            print("✅ Server is running")

        # Step 2: Get server's public key
        print("🔑 Requesting server's public key...")
        res = requests.get("http://127.0.0.1:5000/api/get_public_key")
        
        if res.status_code != 200:
            print(f"❌ Failed to get public key. Status code: {res.status_code}")
            return
        
        # Parse the JSON response correctly
        response_data = res.json()
        server_public_key_hex = response_data["public_key"]
        server_public_key = bytes.fromhex(server_public_key_hex)
        print("✅ Received server's public key")

        # Step 3: Encapsulate shared secret
        print("🔒 Encapsulating shared secret...")
        with oqs.KeyEncapsulation(ALGO) as client_kem:
            ciphertext, shared_secret = client_kem.encap_secret(server_public_key)
        print("🔑 Shared secret established with server")

        # Step 4: Encrypt message using XOR
        print(f"📨 Original message: {message}")
        
        # Make sure we don't run out of shared secret bytes
        if len(shared_secret) < len(message):
            # Repeat the shared secret if needed
            repeated_secret = (shared_secret * (len(message) // len(shared_secret) + 1))[:len(message)]
            encrypted_message = bytes([a ^ b for a, b in zip(message.encode(), repeated_secret)])
        else:
            encrypted_message = bytes([a ^ b for a, b in zip(message.encode(), shared_secret)])
        
        print("🔐 Message encrypted using XOR")

        # Step 5: Send encrypted data to server
        print("📡 Sending encrypted data to server...")
        payload = {
            "ciphertext": ciphertext.hex(),
            "encrypted_message": encrypted_message.hex(),
            "device_type": device_type  # Add device type to identify source
        }

        res = requests.post("http://127.0.0.1:5000/api/send_data", json=payload)

        # Step 6: Handle server response
        if res.status_code == 200:
            try:
                response_data = res.json()
                print("✅ Server response:", response_data)
                if "decrypted" in response_data:
                    print(f"📩 Decrypted message: {response_data['decrypted']}")
            except Exception as e:
                print("❌ Server returned invalid JSON response:")
                print(f"Response text: {res.text}")
        else:
            print(f"❌ Server error: Status code {res.status_code}")

    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure server.py is running on port 5000")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Get device type from command line or use default
    if len(sys.argv) > 1:
        device_type = sys.argv[1]
    else:
        device_type = "sensor1"  # Default device
    
    if device_type not in device_messages:
        print(f"❌ Unknown device type: {device_type}")
        print("Available devices: sensor1, camera1, lock1, light1")
        sys.exit(1)
    
    print(f"🚀 Simulating {device_type} device")
    send_encrypted_message(device_type)