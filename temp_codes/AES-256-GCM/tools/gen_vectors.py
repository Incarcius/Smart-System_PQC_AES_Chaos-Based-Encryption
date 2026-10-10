                     
"""Generate NIST-style AES-256-GCM test vectors using OpenSSL 3.x CLI.

Used once to produce known-good (key, iv, aad, plaintext) -> (ciphertext, tag)
tuples that are baked into tests/test_vectors.inc. These act as the independent
oracle for gcm_core, per design doc §0.5 / §6.
"""
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def gcm256(key_hex, iv_hex, pt_hex, aad_hex=b""):
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    pt = bytes.fromhex(pt_hex)
    aad = bytes.fromhex(aad_hex) if aad_hex else b""
    ct = AESGCM(key).encrypt(iv, pt, aad)
    tag = ct[-16:]
    return ct[:-16].hex(), tag.hex()

vectors = [
                                     
    ("empty-pt-empty-aad",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000", "", ""),
    ("empty-pt-with-aad",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "000000000000000000000000", "feedfacedeadbeeffeedfacedeadbeefabaddad2", ""),
    ("one-block-aes-256-vector",
     "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "cafebabefacedbaddecaf888", "", "d9313225f88406e5a55909c5aff5269a"),
    ("multi-block-16-18-22",
     "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "cafebabefacedbaddecaf888", "",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
    ("multi-block-full-aad",
     "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "cafebabefacedbaddecaf888",
     "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
    ("64-byte-pt-no-aad",
     "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "cafebabefacedbaddecaf888", "",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
     "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
     "22"),                                          
    ("short-7-byte-pt",
     "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "deadbeef"),
    ("24-byte-aad-3-pt",
     "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
     "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeef", "deadbeef"),
]

rows = []
for label, key, iv, aad, pt in vectors:
    ct, tag = gcm256(key, iv, pt, aad)
    rows.append({
        "label": label, "key": key, "iv": iv, "aad": aad, "pt": pt,
        "ct": ct, "tag": tag,
    })

print(json.dumps(rows, indent=2))