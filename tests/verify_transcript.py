import json
import argparse
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# We need to import our own crypto functions to verify
from app.crypto.pki import load_pem_certificate
from app.crypto.sign import verify_signature, get_message_hash

def verify_transcript_file(transcript_path, receipt_path, peer_cert_path):
    """
    Performs offline verification of a transcript and its receipt.
    """
    print(f"--- Verifying Transcript: {transcript_path} ---")
    
    # 1. Load the peer's certificate (public key)
    try:
        peer_cert = load_pem_certificate(peer_cert_path)
        peer_pub_key = peer_cert.public_key()
        print(f"Loaded peer certificate: {peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}")
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return

    # 2. Load the transcript log
    try:
        with open(transcript_path, "r") as f:
            log_lines = f.readlines()
        print(f"Loaded {len(log_lines)} messages from transcript log.")
    except Exception as e:
        print(f"Error loading transcript file: {e}")
        return

    # 3. Load the session receipt
    try:
        with open(receipt_path, "r") as f:
            receipt = json.load(f)
        print(f"Loaded session receipt: {receipt_path}")
    except Exception as e:
        print(f"Error loading receipt file: {e}")
        return

    # --- Test Part 1: Verify Individual Messages ---
    print("\n--- Verifying Individual Message Signatures ---")
    all_msgs_valid = True
    for i, line in enumerate(log_lines):
        try:
            parts = line.strip().split('|')
            seq, ts, ct, sig, fp = parts
            
            # Recompute the hash
            data_hash = get_message_hash(seq, ts, ct)
            
            # Verify the signature
            if not verify_signature(peer_pub_key, data_hash, sig):
                print(f"  [FAIL] Message {seq}: Signature is INVALID")
                all_msgs_valid = False
            else:
                print(f"  [OK] Message {seq}: Signature is valid.")
                
        except Exception as e:
            print(f"  [FAIL] Error processing line {i+1}: {e}")
            all_msgs_valid = False

    if all_msgs_valid:
        print("--- Result: All message signatures are VALID. ---")
    else:
        print("--- Result: INVALID message signatures found! ---")

    # --- Test Part 2: Verify the SessionReceipt ---
    print("\n--- Verifying SessionReceipt Signature ---")
    
    # 1. Recompute the TranscriptHash
    full_transcript_data = "".join(log_lines)
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(full_transcript_data.encode('utf-8'))
    computed_hash = hasher.finalize()
    computed_hash_hex = computed_hash.hex()
    
    print(f"  Computed Transcript Hash: {computed_hash_hex}")
    
    # 2. Get hash and sig from receipt
    receipt_hash_hex = receipt.get("hash")
    receipt_sig = receipt.get("sig")
    
    if receipt_hash_hex != computed_hash_hex:
        print(f"  [FAIL] Hash Mismatch!")
        print(f"    Receipt claims hash: {receipt_hash_hex}")
        print(f"    We computed hash:    {computed_hash_hex}")
        print("--- Result: Transcript has been tampered with! ---")
        return

    print("  [OK] Transcript hash MATCHES receipt hash.")
    
    # 3. Verify the signature over the hash
    if verify_signature(peer_pub_key, computed_hash, receipt_sig):
        print("  [OK] SessionReceipt signature is VALID.")
        print("\n--- FINAL RESULT: SUCCESS! Transcript is authentic and unmodified. ---")
    else:
        print("  [FAIL] SessionReceipt signature is INVALID.")
        print("\n--- FINAL RESULT: FAILED! Receipt signature is invalid. ---")


if __name__ == "__main__":
    # We need to import this to load the crypto modules correctly
    from app.crypto.pki import load_pem_certificate
    from app.crypto.sign import verify_signature, get_message_hash
    from cryptography import x509
    
    parser = argparse.ArgumentParser(description="Offline Transcript Verifier")
    parser.add_argument('--transcript', type=str, required=True, help="Path to the transcript .log file")
    parser.add_argument('--receipt', type=str, required=True, help="Path to the session receipt .json file")
    parser.add_argument('--cert', type=str, required=True, help="Path to the *peer's* public certificate (e.g., client_cert.pem)")
    
    args = parser.parse_args()
    verify_transcript_file(args.transcript, args.receipt, args.cert)