# Smart-System PQC, AES & Chaos-Based Encryption

A highly secure, intelligent telemetry link and gateway-server architecture designed for IoT and smart systems. This project integrates Post-Quantum Cryptography (PQC), Advanced Encryption Standard (AES-GCM), and Adaptive Chaos-Coupled Map (ACCM) for robust, quantum-resistant communication. It also features a machine learning-driven security posture control system using Deep Q-Networks (DQN).

## Key Features

- **Hybrid Cryptography System**: 
  - **AES-GCM**: Provides authenticated symmetric encryption.
  - **ACCM (Adaptive Chaos-Coupled Map)**: Adds a chaotic mask (XOR keystream) over AES output for enhanced unpredictability.
  - **Post-Quantum Cryptography (PQC)**: Future-proofs the system against quantum attacks.
  - **ECDHE & RXCR-KMAC-KDF**: Secure key exchange and key derivation.
- **Intelligent Security Posture**: Utilizes an ML-driven LSTM/DQN model on the server to dynamically monitor telemetry and control the gateway's security posture (NORMAL, SUSPICIOUS, ANOMALY).
- **Resilient Control Plane**: Features a push-based lease mechanism for security directives. If the control channel is dropped or jammed, the gateway automatically escalates its security posture to prevent suppression attacks.
- **Hardware Support**: Optimized for edge deployment on ESP32 microcontrollers and embedded Gateways.
- **Strict Anti-Replay & Nonce Guards**: Ensures nonces are unique across sessions and reboots, with strict receiver-side replay guards and monotonically increasing sequence counters.

## Project Structure

- `src/` & `include/`: Core C implementation of the telemetry protocol, serialization, nonce/replay guards, and posture control state machine.
- `src/security/`: Cryptographic primitives including ACCM, AES-GCM, ECDHE, PQC, and KDF.
- `src/ML/`: Machine learning policies including the Deep Q-Network (DQN) implementation.
- `src/hardware/`: Hardware-specific bindings for ESP32 and Gateway platforms.
- `server/`: Server-side components (Python) for telemetry ingestion, LSTM anomaly detection, and issuing authenticated control leases.
- `docs/` & `paper/`: System design documentation and related research papers.

## Building and Usage

This project uses CMake for the C gateway components.

```bash
mkdir build
cd build
cmake ..
make
```

## Protocol Architecture

The telemetry link ensures the highest level of data integrity and confidentiality:
1. **Plaintext** ->
2. **AES-256-GCM** (Key = Session Key, Nonce = Deterministic, AAD = Serialized Header) ->
3. **Ciphertext & Tag** ->
4. **ACCM Chaotic Mask** (XOR Keystream) ->
5. **Wire Format**: `Header (Cleartext) || Masked (Ciphertext || Tag)`

The cleartext header is authenticated as AAD in the AES-GCM step, ensuring that any manipulation of the security posture, sequence numbers, or timestamps results in an immediate GCM tag validation failure.

## License

(Add your license here)