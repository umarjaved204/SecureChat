import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class TranscriptLogger:
    def __init__(self, peer_name):
        self.log_lines = []
        self.filename = f"transcripts/{peer_name}_{int(time.time())}.log"
        
        # Ensure the transcripts directory exists
        os.makedirs("transcripts", exist_ok=True)
        
        print(f"[Transcript] Logging to {self.filename}")

    def log_message(self, seqno, timestamp, ct, sig, cert_fingerprint):
        """
        Logs a single message in the format:
        seqno | timestamp | ciphertext | sig | peer-cert-fingerprint
        
        """
        line = f"{seqno}|{timestamp}|{ct}|{sig}|{cert_fingerprint}\n"
        self.log_lines.append(line)
        
        # Append to file
        with open(self.filename, "a") as f:
            f.write(line)

    def get_transcript_hash(self):
        """
        Computes SHA256(concatenation of all log lines)
        [cite: 226]
        """
        full_transcript = "".join(self.log_lines)
        
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(full_transcript.encode('utf-8'))
        return hasher.finalize()