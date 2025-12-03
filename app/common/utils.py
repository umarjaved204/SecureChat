import json
import socket
import struct

# --- Networking Functions ---

def send_message(sock, data):
    """
    Sends a JSON-serializable message over a socket.
    Prefixes the message with its 4-byte length.
    """
    try:
        json_data = json.dumps(data).encode('utf-8')
        len_prefix = struct.pack('>I', len(json_data))
        sock.sendall(len_prefix + json_data)
        return True
    except (socket.error, OverflowError, json.JSONDecodeError) as e:
        print(f"Error sending message: {e}")
        return False

def receive_message(sock):
    """
    Receives a length-prefixed JSON message from a socket.
    """
    try:
        # Read the 4-byte length prefix
        len_prefix = sock.recv(4)
        if not len_prefix:
            return None  # Connection closed
        
        msg_len = struct.unpack('>I', len_prefix)[0]
        
        # Read the full message
        msg_data = b''
        while len(msg_data) < msg_len:
            chunk = sock.recv(msg_len - len(msg_data))
            if not chunk:
                return None  # Connection closed unexpectedly
            msg_data += chunk
            
        return json.loads(msg_data.decode('utf-8'))
    
    except (socket.error, struct.error, json.JSONDecodeError) as e:
        print(f"Error receiving message: {e}")
        return None