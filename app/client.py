import socket
import json         
import getpass      
import sys
import threading
import select
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from app.common.utils import send_message, receive_message
from app.crypto.pki import load_pem_certificate, load_pem_private_key, \
                           serialize_certificate, deserialize_certificate, \
                           validate_certificate
from app.crypto.dh import dh_generate_key_pair, dh_compute_shared_secret, \
                          derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_message, verify_signature, get_message_hash
from app.storage.transcript import TranscriptLogger

# Global flag to signal threads to stop
stop_thread = False
# Use a lock for printing to avoid garbled output
print_lock = threading.Lock()

def safe_print(message):
    """Prints messages safely from multiple threads."""
    with print_lock:
        # Clear the current line (for user input)
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        print(message)
        # Re-print the input prompt
        sys.stdout.write("Enter message (or 'quit'): ")
        sys.stdout.flush()

def receive_chat_messages(sock, session_key, server_cert, transcript):
    """
    Thread target function to listen for incoming chat messages.
    """
    global stop_thread
    server_pub_key = server_cert.public_key()
    server_cert_fp = server_cert.fingerprint(hashes.SHA256()).hex()
    
    while not stop_thread:
        try:
            ready_to_read, _, _ = select.select([sock], [], [], 0.1)
            if not ready_to_read:
                continue

            msg = receive_message(sock)
            if msg is None:
                safe_print("[System] Connection closed by server.")
                stop_thread = True
                break

            if msg.get("type") == "msg":
                # --- Verification (Section 2.4) ---
                seq = msg.get("seqno")
                ts = msg.get("ts")
                ct = msg.get("ct")
                sig = msg.get("sig")

                # 1. Verify signature
                data_hash = get_message_hash(seq, ts, ct)
                if not verify_signature(server_pub_key, data_hash, sig):
                    safe_print(f"[System] SIGNATURE VERIFICATION FAILED for seq {seq}!")
                    continue

                # 2. Decrypt ciphertext
                plaintext = aes_decrypt(session_key, ct)
                if plaintext is None:
                    safe_print(f"[System] DECRYPTION FAILED for seq {seq}!")
                    continue
                
                # 3. Log to transcript
                transcript.log_message(seq, ts, ct, sig, server_cert_fp)

                safe_print(f"{plaintext}")

            elif msg.get("type") == "error":
                safe_print(f"[Server Error] {msg.get('message')}")

        except Exception as e:
            if not stop_thread:
                safe_print(f"[System] Error in receiver thread: {e}")
            break
    safe_print("[System] Receiver thread stopping.")

def main():
    global stop_thread
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    session_aes_key = None
    transcript = None
    client_key = None
    
    try:
        client_socket.connect(('localhost', 12345))
        print("[Client] Connected to server.")

        # --- Section 2.1: PKI & Mutual Auth ---
        print("[Client] Loading credentials...")
        client_cert = load_pem_certificate("certs/client_cert.pem")
        client_key = load_pem_private_key("certs/client_key.pem")
        ca_cert = load_pem_certificate("certs/ca_cert.pem")

        client_hello = { "type": "hello", "client_cert": serialize_certificate(client_cert).decode('utf-8'), "nonce": "..." }
        send_message(client_socket, client_hello)
        print("[Client] Sent client hello.")

        server_hello = receive_message(client_socket)
        if not server_hello or server_hello.get("status") == "error":
            print(f"[Client] Server error: {server_hello.get('message', 'Unknown')}")
            return
        if server_hello.get("type") != "server_hello":
            print("[Client] Invalid message from server.")
            return

        print("[Client] Received server hello.")
        server_cert_pem = server_hello.get("server_cert")
        server_cert = deserialize_certificate(server_cert_pem.encode('utf-8'))
        
        is_valid, reason = validate_certificate(server_cert, ca_cert)
        if not is_valid:
            print(f"[Client] Server certificate validation failed: {reason}")
            return
        
        try:
            sans = server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns_names = sans.get_values_for_type(x509.DNSName)
            if "localhost" not in dns_names: raise Exception("Hostname 'localhost' not in SAN")
        except Exception as e:
            print(f"[Client] Hostname validation failed: {e}")
            return
            
        print("[Client] Server certificate validated.")
        print("--- MUTUAL AUTHENTICATION SUCCESSFUL ---")

        # --- Section 2.2: Temporary DH Exchange (for Login) ---
        print("[Client] Generating temporary DH key pair...")
        client_dh_private, client_dh_public = dh_generate_key_pair()
        send_message(client_socket, { "type": "dh_init_client", "public_key": client_dh_public.decode('utf-8') })
        print("[Client] Sent temporary DH public key.")

        dh_resp_msg = receive_message(client_socket)
        if not dh_resp_msg or dh_resp_msg.get("type") != "dh_init_server":
            print("[Client] Did not receive server temporary DH response.")
            return
        
        server_dh_public = dh_resp_msg.get("public_key").encode('utf-8')
        print("[Client] Received server temporary DH public key.")
        shared_secret = dh_compute_shared_secret(client_dh_private, server_dh_public)
        temp_aes_key = derive_aes_key(shared_secret)
        
        # --- Section 2.2: Registration / Login ---
        action = input("Do you want to (1) Register or (2) Login? ")
        
        if action == "1":
            email = input("Enter email: ")
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            auth_data = { "type": "register", "email": email, "username": username, "password": password }
        elif action == "2":
            email = input("Enter email: ")
            password = getpass.getpass("Enter password: ")
            auth_data = { "type": "login", "email": email, "password": password }
        else:
            print("Invalid option. Disconnecting.")
            return

        encrypted_payload = aes_encrypt(temp_aes_key, json.dumps(auth_data))
        send_message(client_socket, { "type": "encrypted_auth", "payload": encrypted_payload })
        print("[Client] Sent encrypted auth credentials.")
        
        response = receive_message(client_socket)
        if not response:
            print("[Client] No response from server.")
            return
            
        print(f"[Server Response] Status: {response.get('status')}")
        print(f"[Server Response] Message: {response.get('message')}")
        
        # --- Section 2.3: Main Session Key Exchange ---
        if response.get("status") == "success" and action == "2":
            print("\n[Client] Login successful. Establishing main session key...")
            
            client_dh_private, client_dh_public = dh_generate_key_pair()
            send_message(client_socket, { "type": "dh_main_client", "public_key": client_dh_public.decode('utf-8') })
            print("[Client] Sent MAIN DH public key.")

            dh_main_resp = receive_message(client_socket)
            if not dh_main_resp or dh_main_resp.get("type") != "dh_main_server":
                print("[Client] Did not receive server MAIN DH response.")
                return

            server_dh_public = dh_main_resp.get("public_key").encode('utf-8')
            print("[Client] Received server MAIN DH public key.")
            
            shared_secret = dh_compute_shared_secret(client_dh_private, server_dh_public)
            session_aes_key = derive_aes_key(shared_secret)
            print(f"[Client] MAIN SESSION KEY established.")
            
            # --- Section 2.4: Chat Loop ---
            print("\n--- Secure Chat Started ---")
            
            transcript = TranscriptLogger("client")
            seq_num = 0
            
            receiver_thread = threading.Thread(
                target=receive_chat_messages, 
                args=(client_socket, session_aes_key, server_cert, transcript)
            )
            receiver_thread.daemon = True
            receiver_thread.start()

            time.sleep(0.1)
            sys.stdout.write("Enter message (or 'quit'): ")
            sys.stdout.flush()

            while not stop_thread:
                ready_to_read, _, _ = select.select([sys.stdin], [], [], 0.1)
                
                if ready_to_read:
                    plaintext = sys.stdin.readline().strip()
                    if plaintext == "quit":
                        stop_thread = True
                        break
                    if not plaintext:
                        sys.stdout.write("Enter message (or 'quit'): ")
                        sys.stdout.flush()
                        continue

                    # --- Create Secure Message (Section 2.4) ---
                    seq_num += 1
                    timestamp = int(time.time() * 1000)
                    
                    ciphertext = aes_encrypt(session_aes_key, plaintext)
                    data_hash = get_message_hash(seq_num, timestamp, ciphertext)
                    signature = sign_message(client_key, data_hash)
                    
                    client_cert_fp = client_cert.fingerprint(hashes.SHA256()).hex()
                    transcript.log_message(seq_num, timestamp, ciphertext, signature, client_cert_fp)

                    msg = {
                        "type": "msg",
                        "seqno": seq_num,
                        "ts": timestamp,
                        "ct": ciphertext,
                        "sig": signature
                    }
                    if not send_message(client_socket, msg):
                        safe_print("[System] Failed to send message. Connection may be lost.")
                        stop_thread = True
                    else:
                        sys.stdout.write("Enter message (or 'quit'): ")
                        sys.stdout.flush()
            
            # --- Section 2.5: Generate Client's Receipt ---
            # This code runs after user types 'quit'
            print("\n[Client] Generating local SessionReceipt...")
            t_hash = transcript.get_transcript_hash()
            t_sig = sign_message(client_key, t_hash)
            
            receipt = {
                "type": "receipt",
                "peer": "client",
                "hash": t_hash.hex(),
                "sig": t_sig
            }
            
            # Send receipt to server
            send_message(client_socket, receipt)
            
            # Save the receipt locally
            receipt_filename = f"transcripts/receipt_client_{transcript.filename.split('_')[-1].split('.')[0]}.json"
            with open(receipt_filename, "w") as f:
                json.dump(receipt, f, indent=2)
            print(f"[Client] Client-side receipt saved to {receipt_filename}")
            
            receiver_thread.join(timeout=1.0)

    except KeyboardInterrupt:
        print("\n[Client] Interrupted by user.")
    except Exception as e:
        print(f"\n[Client] Error: {e}")
    finally:
        stop_thread = True
        print("[Client] Closing connection.")
        client_socket.close()

if __name__ == "__main__":
    main()