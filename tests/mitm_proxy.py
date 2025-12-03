import socket
import threading
import json
import base64
import struct

def send_message(sock, data):
    try:
        json_data = json.dumps(data).encode('utf-8')
        len_prefix = struct.pack('>I', len(json_data))
        sock.sendall(len_prefix + json_data)
        return True
    except Exception as e:
        print(f"[Proxy] Error sending: {e}")
        return False

def receive_message(sock):
    try:
        len_prefix = sock.recv(4)
        if not len_prefix: return None
        msg_len = struct.unpack('>I', len_prefix)[0]
        
        msg_data = b''
        while len(msg_data) < msg_len:
            chunk = sock.recv(msg_len - len(msg_data))
            if not chunk: return None
            msg_data += chunk
        return json.loads(msg_data.decode('utf-8'))
    except Exception as e:
        print(f"[Proxy] Error receiving: {e}")
        return None
# --- End of protocol code ---

# Flag to ensure we only tamper with one message
tampered = False

def tamper_packet(payload):
    """
    Finds the 'ct' (ciphertext) field and flips a single bit.
    """
    global tampered
    if payload.get("type") == "msg" and not tampered:
        print("[Proxy] ---> Intercepted a 'msg' packet. TAMPERING...")
        try:
            # Decode the ciphertext from Base64
            ct_b64 = payload["ct"]
            ct_bytes = base64.b64decode(ct_b64)
            
            # Flip the first bit of the first byte
            original_byte = ct_bytes[0]
            tampered_byte = original_byte ^ 1 # XOR with 1 flips the last bit
            
            # Create the new tampered byte string
            tampered_ct_bytes = bytes([tampered_byte]) + ct_bytes[1:]
            
            # Re-encode to Base64
            tampered_ct_b64 = base64.b64encode(tampered_ct_bytes).decode('utf-8')
            
            # Replace the ciphertext in the message
            payload["ct"] = tampered_ct_b64
            tampered = True
            print("[Proxy] ---> Bit flipped! Forwarding tampered packet to server.")
            
        except Exception as e:
            print(f"[Proxy] Error during tampering: {e}")
            
    return payload

def handle_client_to_server(client_sock, server_sock):
    """Relays data from client to server, tampering on the way."""
    try:
        while True:
            msg = receive_message(client_sock)
            if msg is None: break
            
            print(f"[Proxy] C->S: {msg.get('type')}")
            
            # *** THIS IS THE ATTACK ***
            msg = tamper_packet(msg)
            # **************************
            
            if not send_message(server_sock, msg):
                break
    finally:
        client_sock.close()
        server_sock.close()

def handle_server_to_client(server_sock, client_sock):
    """Relays data from server to client (no tampering)."""
    try:
        while True:
            msg = receive_message(server_sock)
            if msg is None: break
            
            print(f"[Proxy] S->C: {msg.get('type')}")
            
            if not send_message(client_sock, msg):
                break
    finally:
        client_sock.close()
        server_sock.close()

def main():
    proxy_host = 'localhost'
    proxy_port = 12346  # We will listen on this port
    server_host = 'localhost'
    server_port = 12345 # The real server
    
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((proxy_host, proxy_port))
    proxy_socket.listen(5)
    
    print(f"[Proxy] Listening on {proxy_host}:{proxy_port}")
    print(f"[Proxy] Forwarding to {server_host}:{server_port}")
    
    try:
        while True:
            client_sock, client_addr = proxy_socket.accept()
            print(f"[Proxy] Accepted connection from {client_addr}")
            
            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.connect((server_host, server_port))
                print(f"[Proxy] Connected to real server at {server_host}:{server_port}")
                
                # Start threads to relay data
                c2s_thread = threading.Thread(target=handle_client_to_server, args=(client_sock, server_sock))
                s2c_thread = threading.Thread(target=handle_server_to_client, args=(server_sock, client_sock))
                
                c2s_thread.start()
                s2c_thread.start()
                
            except Exception as e:
                print(f"[Proxy] Failed to connect to server: {e}")
                client_sock.close()
                
    except KeyboardInterrupt:
        print("\n[Proxy] Shutting down.")
    finally:
        proxy_socket.close()

if __name__ == "__main__":
    main()