import socket
import json
import threading
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

from app.storage import db as database
from app.common.utils import send_message, receive_message
from app.crypto.pki import load_pem_certificate, load_pem_private_key, \
                           serialize_certificate, deserialize_certificate, \
                           validate_certificate
from app.crypto.dh import dh_generate_key_pair, dh_compute_shared_secret, \
                          derive_aes_key
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_message, verify_signature, get_message_hash
from app.storage.transcript import TranscriptLogger

# --- Globals ---
clients_lock = threading.Lock()
connected_clients = {}
server_key = None
server_cert = None
# ----------------

def broadcast_message(sender_sock, message, seq_num, timestamp, ct, sig):
    """
    Broadcasts a verified message to all other connected clients.
    """
    with clients_lock:
        # Log to server's transcript for the sender
        sender_cert_fp = connected_clients[sender_sock]["cert"].fingerprint(hashes.SHA256()).hex()
        connected_clients[sender_sock]["transcript"].log_message(seq_num, timestamp, ct, sig, sender_cert_fp)

        # Re-encrypt and sign for each recipient
        for sock, client_info in connected_clients.items():
            if sock == sender_sock:
                continue 
            
            recipient_key = client_info["session_key"]
            
            # 1. Encrypt for recipient
            plaintext = aes_decrypt(connected_clients[sender_sock]["session_key"], ct)
            sender_cn = connected_clients[sender_sock]["cert"].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            recipient_ct = aes_encrypt(recipient_key, f"[{sender_cn}]: {plaintext}")
            
            # 2. Hash
            b_seq = int(time.time())
            b_ts = int(time.time() * 1000)
            data_hash = get_message_hash(b_seq, b_ts, recipient_ct)
            
            # 3. Sign with SERVER's key
            b_sig = sign_message(server_key, data_hash)
            
            # 4. Log to recipient's transcript
            server_cert_fp = server_cert.fingerprint(hashes.SHA256()).hex()
            client_info["transcript"].log_message(b_seq, b_ts, recipient_ct, b_sig, server_cert_fp)
            
            # 5. Send
            b_msg = { "type": "msg", "seqno": b_seq, "ts": b_ts, "ct": recipient_ct, "sig": b_sig }
            send_message(sock, b_msg)


def handle_client(client_socket):
    print(f"[Server] Client connected: {client_socket.getpeername()}")
    temp_aes_key = None
    session_aes_key = None
    client_cert = None
    client_addr = client_socket.getpeername()
    
    try:
        # --- Section 2.1: PKI & Mutual Auth ---
        ca_cert = load_pem_certificate("certs/ca_cert.pem")

        client_hello = receive_message(client_socket)
        if not client_hello or client_hello.get("type") != "hello":
            print("[Server] Failed to receive client hello.")
            return

        client_cert_pem = client_hello.get("client_cert")
        client_cert = deserialize_certificate(client_cert_pem.encode('utf-8'))

        is_valid, reason = validate_certificate(client_cert, ca_cert)
        if not is_valid:
            print(f"[Server] Client certificate validation failed: {reason}")
            send_message(client_socket, {"status": "error", "message": reason})
            return
        
        print(f"[Server] Client certificate validated for {client_addr}.")

        server_hello = { "type": "server_hello", "server_cert": serialize_certificate(server_cert).decode('utf-8'), "nonce": "..." }
        send_message(client_socket, server_hello)
        
        # --- Section 2.2: Temporary DH Exchange (for Login) ---
        dh_init_msg = receive_message(client_socket)
        client_dh_public = dh_init_msg.get("public_key").encode('utf-8')
        server_dh_private, server_dh_public = dh_generate_key_pair()
        send_message(client_socket, { "type": "dh_init_server", "public_key": server_dh_public.decode('utf-8') })
        shared_secret = dh_compute_shared_secret(server_dh_private, client_dh_public)
        temp_aes_key = derive_aes_key(shared_secret)

        # --- Section 2.2: Registration / Login ---
        auth_msg = receive_message(client_socket)
        encrypted_payload = auth_msg.get("payload")
        decrypted_json_str = aes_decrypt(temp_aes_key, encrypted_payload)
        auth_data = json.loads(decrypted_json_str)
        print(f"[Server] Received auth type: {auth_data.get('type')} from {client_addr}")
        
        response = {}
        if auth_data.get("type") == "register":
            success, message = database.register_user(auth_data.get("email"), auth_data.get("username"), auth_data.get("password"))
            response = {"status": "success" if success else "error", "message": message}
        elif auth_data.get("type") == "login":
            success, message = database.verify_user(auth_data.get("email"), auth_data.get("password"))
            response = {"status": "success" if success else "error", "message": message}
        
        send_message(client_socket, response)
        print(f"[Server] Sent response to client {client_addr}: {response}")

        # --- Section 2.3: Main Session Key Exchange ---
        if response.get("status") == "success" and auth_data.get("type") == "login":
            print(f"[Server] Login successful for {client_addr}. Establishing main session key...")
            
            dh_main_msg = receive_message(client_socket)
            client_dh_public = dh_main_msg.get("public_key").encode('utf-8')
            
            server_dh_private, server_dh_public = dh_generate_key_pair()
            send_message(client_socket, { "type": "dh_main_server", "public_key": server_dh_public.decode('utf-8') })
            
            shared_secret = dh_compute_shared_secret(server_dh_private, client_dh_public)
            session_aes_key = derive_aes_key(shared_secret)
            print(f"[Server] MAIN SESSION KEY established for {client_addr}.")

            # --- Add client to the broadcast list ---
            with clients_lock:
                connected_clients[client_socket] = {
                    "session_key": session_aes_key,
                    "cert": client_cert,
                    "last_seqno_seen": 0, # <-- CHANGED: Renamed for clarity
                    "transcript": TranscriptLogger(f"server_for_{client_addr[1]}")
                }
            print(f"[Server] Client {client_addr} added to chat.")
            
            # --- Section 2.4: Chat Loop ---
            client_pub_key = client_cert.public_key()
            
            while True:
                msg = receive_message(client_socket)
                if msg is None:
                    break # Client disconnected

                if msg.get("type") == "msg":
                    seq, ts, ct, sig = msg.get("seqno"), msg.get("ts"), msg.get("ct"), msg.get("sig")
                    
                    # --- NEW CODE: REPLAY PROTECTION ---
                    # 
                    client_info = connected_clients[client_socket]
                    if seq <= client_info["last_seqno_seen"]:
                        print(f"[Server] REPLAY DETECTED from {client_addr}. Seq: {seq}, LastSeen: {client_info['last_seqno_seen']}")
                        send_message(client_socket, {"type": "error", "message": "REPLAY: Message seqno is not strictly increasing."})
                        continue # Discard
                    
                    # Update the last seen sequence number
                    client_info["last_seqno_seen"] = seq
                    # --- END OF NEW CODE ---
                    
                    # 1. Verify signature
                    data_hash = get_message_hash(seq, ts, ct)
                    if not verify_signature(client_pub_key, data_hash, sig):
                        print(f"[Server] SIGNATURE FAILED from {client_addr}")
                        continue
                    
                    # 2. Decrypt
                    plaintext = aes_decrypt(session_aes_key, ct)
                    if plaintext is None:
                        print(f"[Server] DECRYPTION FAILED from {client_addr}")
                        continue
                    
                    print(f"[Server] Received '{plaintext}' from {client_addr}. Broadcasting...")
                    
                    # 3. Broadcast to all *other* clients
                    broadcast_message(client_socket, plaintext, seq, ts, ct, sig)

                # --- Section 2.5: Handle Client Receipt ---
                elif msg.get("type") == "receipt":
                    print(f"[Server] Received SessionReceipt from {client_addr}")
                    t_hash_hex = msg.get("hash")
                    t_sig = msg.get("sig")
                    t_hash_bytes = bytes.fromhex(t_hash_hex)
                    
                    # 1. Verify client's signature on their receipt
                    if verify_signature(client_pub_key, t_hash_bytes, t_sig):
                        print(f"[Server] Client SessionReceipt signature is VALID for {client_addr}.")
                    else:
                        print(f"[Server] Client SessionReceipt signature is INVALID for {client_addr}.")
                    
                    # 2. Verify the hash matches our own transcript
                    server_t_hash_hex = connected_clients[client_socket]["transcript"].get_transcript_hash().hex()
                    if server_t_hash_hex == t_hash_hex:
                        print(f"[Server] Client TranscriptHash MATCHES server's for {client_addr}.")
                    else:
                        print(f"[Server] Client TranscriptHash MISMATCH for {client_addr}.")
                    
                    break # Client is done, break loop
        else:
            print(f"[Server] Login failed for {client_addr}. Closing connection.")
        
    except Exception as e:
        print(f"[Server] Error handling client {client_addr}: {e}")
    finally:
        # --- Section 2.5: Generate Server's Receipt ---
        with clients_lock:
            if client_socket in connected_clients:
                print(f"[Server] Generating SessionReceipt for {client_addr}...")
                transcript = connected_clients[client_socket]["transcript"]
                t_hash = transcript.get_transcript_hash()
                t_sig = sign_message(server_key, t_hash)
                
                receipt = {
                    "type": "receipt",
                    "peer": "server",
                    "hash": t_hash.hex(),
                    "sig": t_sig
                }
                
                # Save the receipt to a file
                receipt_filename = f"transcripts/receipt_server_for_{client_addr[1]}.json"
                with open(receipt_filename, "w") as f:
                    json.dump(receipt, f, indent=2)
                print(f"[Server] Server-side receipt saved to {receipt_filename}")
                
                del connected_clients[client_socket]
        
        print(f"[Server] Client {client_addr} disconnected.")
        client_socket.close()

def main():
    global server_key, server_cert
    database.init_db()
    
    print("[Server] Loading server credentials...")
    server_key = load_pem_private_key("certs/server_key.pem")
    server_cert = load_pem_certificate("certs/server_cert.pem")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    print("[Server] Listening on localhost:12345...")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()