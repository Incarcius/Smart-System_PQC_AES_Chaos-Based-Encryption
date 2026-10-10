// Second paper: full system treatment, SmartMediQ template.
//
// No em dashes, no en dashes. Hardware figures are placeholders and are
// labelled as such in the table title, in a status column, and in the prose.

module.exports = function content(API) {
  const { body, bullet, section, subsection, caption, figure, gap, gridTable,
          tableCaption, COL_DXA } = API;
  const B = [];
  const W = (f) => Math.round(COL_DXA * f);

  // ───────────────────────── Abstract ─────────────────────────
  B.push(body([
    { t: "Abstract: ", b: true },
    { t: "Industrial Internet of Things deployments in electrical " +
         "transmission face two problems that conventional designs address " +
         "separately and badly. Telemetry recorded today may be decrypted by " +
         "an adversary who acquires quantum capability inside the twenty year " +
         "service life of the equipment, and a capable adversary attacks the " +
         "operator's visibility at the same time as the plant, so a control " +
         "plane that assumes a reachable server fails exactly when it is " +
         "needed. This paper presents a three tier telemetry architecture " +
         "that addresses both. A control server establishes root keys with " +
         "field gateways using ML-KEM-512 encapsulation authenticated by " +
         "ML-DSA-44, while constrained sensor nodes run only an X25519 " +
         "exchange bound to a provisioned pre shared key, keeping lattice " +
         "arithmetic off the hardware that cannot afford it. Session keys " +
         "derive through an extract and expand function with a SHA3-256 floor " +
         "and KMACXOF256 expansion domain separated per node and per purpose. " +
         "Frames are sealed with AES-256-GCM under a deterministic 96 bit " +
         "nonce whose uniqueness is structural rather than probabilistic, and " +
         "an adaptive coupled chaotic map applies posture dependent masking " +
         "outside the authenticated encryption. Key lifecycle decisions are " +
         "made by a duelling double deep Q network trained against a " +
         "distribution of detector qualities rather than a fixed detector, " +
         "and anomaly scores come from a long short term memory autoencoder " +
         "trained on benign traffic only. Authority is carried by a " +
         "cryptographically sealed lease whose expiry escalates the gateway " +
         "security posture without external instruction. Against a threshold " +
         "rule the learned controller leaves 74 percent less time under " +
         "adversary control while performing 76 percent fewer key rotations, " +
         "winning on all 15 evaluation seeds and all 27 detector settings " +
         "tested, and continuing to win in a disturbance regime outside its " +
         "training distribution. The integrated system passes 24 of 24 " +
         "behavioural checks at a 95th percentile cycle time of 41 ms against " +
         "a one second budget. We additionally report five measurement " +
         "failures encountered during development, three of which generalise " +
         "beyond this system.", b: true },
  ], { noIndent: true }));
  B.push(body([
    { t: "Keywords: ", b: true },
    { t: "post-quantum cryptography, industrial control systems, key " +
         "management, reinforcement learning, anomaly detection, chaotic " +
         "masking, SCADA security, smart grid.", b: true },
  ], { noIndent: true }));

  // ───────────────────────── I. Introduction ─────────────────────────
  B.push(section("I", "Introduction"));
  B.push(body("Electrical transmission infrastructure is being instrumented " +
    "at a pace that its security practice has not matched. Phasor " +
    "measurement units, protection relays and distributed sensing now produce " +
    "continuous telemetry that feeds automated control, and that telemetry " +
    "travels over links which were designed when the threat model was " +
    "accidental failure rather than deliberate attack."));
  B.push(body("Three properties distinguish this setting from general " +
    "purpose Internet of Things security. First, individual measurements " +
    "carry little value while the aggregate is operationally decisive, so an " +
    "adversary gains from passive collection over long periods rather than " +
    "from any single frame. Second, substation equipment is commissioned for " +
    "service lives measured in decades, which places traffic captured today " +
    "plausibly within reach of an adversary who acquires cryptographically " +
    "relevant quantum capability before that equipment is retired. The harvest " +
    "now and decrypt later posture is therefore not speculative for this " +
    "class of system; it is the expected adversary behaviour."));
  B.push(body("Third, and most consequential for the architecture, the 2015 " +
    "attack on the Ukrainian distribution network established that a capable " +
    "adversary attacks the operator's visibility alongside the plant itself " +
    "[23]. Operators were locked out of their own consoles while breakers were " +
    "opened. Any design in which a central server makes every security " +
    "decision inherits a single point of failure that the adversary is " +
    "specifically motivated to attack, and it fails at precisely the moment " +
    "its decisions matter most."));
  B.push(body("A fourth difficulty is less often stated. The quantity a key " +
    "management policy would most like to condition on, whether an adversary " +
    "currently holds a live session key, is never observable. What is " +
    "available is an anomaly score produced by a detector of unknown and " +
    "changing quality. A rotation policy tuned to one detector is tuned to " +
    "that detector's particular error profile, and in practice the detector is " +
    "the component that is retrained most often and last."));
  B.push(body("This paper presents a complete three tier architecture that " +
    "responds to all four. Its contributions are:"));
  B.push(bullet([{ t: "A post quantum key hierarchy that places lattice " +
    "primitives at the gateway and server while leaving sensor nodes on " +
    "elliptic curve operations bound to pre shared material, so that the " +
    "most constrained tier is never asked to perform the most expensive " +
    "operation." }]));
  B.push(bullet([{ t: "A learned key lifecycle controller trained against a " +
    "distribution of detector qualities rather than a single detector, which " +
    "transfers to detector behaviour outside its training distribution." }]));
  B.push(bullet([{ t: "A lease based control plane in which authority " +
    "expires rather than being commanded, posture adoption is verified by " +
    "echo in the authenticated header, and lease expiry deliberately never " +
    "quarantines, so that jamming the control channel cannot be converted " +
    "into a denial of service." }]));
  B.push(bullet([{ t: "An end to end implementation evaluated on a public " +
    "power system attack corpus and in an integrated behavioural harness, " +
    "together with five measurement failures reported in full." }]));

  // ───────────────────────── II. Literature review ─────────────────────────
  B.push(section("II", "Literature Review"));

  B.push(subsection("A", "The Quantum Threat and Its Timeline"));
  B.push(body("Shor algorithm reduces integer factorisation and discrete " +
    "logarithm to polynomial time on a sufficiently large quantum computer " +
    "[9], which would break RSA and elliptic curve key establishment " +
    "outright. Grover algorithm provides a quadratic speedup against " +
    "symmetric primitives [10], which is addressed by doubling key length " +
    "rather than by replacing the primitive, and is the reason this " +
    "architecture uses AES-256 rather than AES-128 for the uplink."));
  B.push(body("The operational question is timing rather than possibility. " +
    "Current superconducting devices achieve single qubit fidelities near " +
    "99.9 percent, far from the error rates required for the circuit depths " +
    "that cryptanalysis demands, and error correction imposes a large " +
    "physical to logical qubit overhead: recent architectures require tens " +
    "of physical qubits per logical qubit and still exhibit per cycle error " +
    "rates of a few percent [11]. Resource estimates for applying Grover to " +
    "AES-256 run to millions of physical qubits once correction is " +
    "accounted for [10], and qubit coherence times measured in microseconds " +
    "to milliseconds remain far below what deep circuits require."));
  B.push(body("None of this makes the threat irrelevant to the system " +
    "considered here, and the reason is specific to the sector. Substation " +
    "equipment is commissioned for service lives of two decades or more, so " +
    "the relevant comparison is not between today capability and today " +
    "traffic but between the capability available at any point in that " +
    "service life and traffic recorded at its start. A harvest now and " +
    "decrypt later adversary needs only storage today and capability " +
    "eventually."));

  B.push(subsection("B", "Post-Quantum Cryptography for Constrained Devices"));
  B.push(body("The standardisation of ML-KEM [1] and ML-DSA [2] has moved " +
    "lattice based key establishment from research into deployment planning. " +
    "For industrial devices the operative question is no longer which scheme " +
    "but where in a topology its cost can be absorbed. Published measurements " +
    "place ML-KEM-512 encapsulation well within the capability of a modern " +
    "single board computer, while an eight bit or low end thirty two bit " +
    "microcontroller with tens of kilobytes of working memory remains a poor " +
    "host for the key sizes involved. Work on quantum resistant " +
    "authentication for grid communications [35] has explored distribution of " +
    "quantum keys over utility fibre, which addresses a different " +
    "deployment profile from the one considered here."));

  B.push(body("The practical obstacle is not computation alone but memory " +
    "and message size. ML-KEM-512 public keys and ciphertexts are measured in " +
    "hundreds of bytes against the tens of bytes typical of elliptic curve " +
    "equivalents, which interacts badly with constrained link layers and with " +
    "devices whose entire working memory is a few tens of kilobytes. Several " +
    "deployment studies therefore conclude that hybrid arrangements, in which " +
    "post quantum material protects long lived secrets while conventional " +
    "primitives handle high frequency operations, are the realistic path for " +
    "existing industrial estates. The architecture presented here takes that " +
    "position and makes the tier boundary explicit."));

  B.push(body("Deployment carries risks that are distinct from the " +
    "mathematics. Lattice schemes have proved susceptible to timing and " +
    "power analysis in implementation [15], and the KyberSlash class of " +
    "attack showed that small timing differences during decapsulation can " +
    "leak key material. Classical primitives have had two decades of side " +
    "channel hardening that post quantum implementations have not yet " +
    "received. Migration is also not a drop in substitution: handshake " +
    "flows, key distribution logic and certificate structures all change, " +
    "and hybrid deployments that run classical and post quantum schemes " +
    "together increase both message size and computational cost while " +
    "retaining the classical exposure [16]."));
  B.push(body("A further caution concerns the security assumptions " +
    "themselves. Lattice hardness provides qualitative rather than " +
    "quantitative assurance at concrete parameter sets [12], [13], in " +
    "contrast to the decades of cryptanalytic attention that have produced " +
    "sharp estimates for RSA. No efficient quantum attack against lattice " +
    "constructions is known, but structural weakness of the kind Shor " +
    "exploited in number theory cannot be excluded. This is an argument for " +
    "cryptographic agility, which the key epoch mechanism of Section IV-D " +
    "provides, rather than an argument against adoption."));
  B.push(body("Benchmarks on constrained hardware consistently find " +
    "lattice key establishment feasible on gateway class devices and " +
    "marginal on microcontrollers [14], [17], which is the empirical basis " +
    "for the tier boundary adopted here."));

  B.push(subsection("C", "Key Management and Rotation in Industrial Systems"));
  B.push(body("IEC 62351 [8] specifies security services for power system " +
    "communications but leaves rotation cadence to the implementer, and in " +
    "practice fixed interval or manual rotation dominates. Fixed interval " +
    "rotation is simple to audit and structurally unable to respond to " +
    "evidence: an interval short enough to limit exposure during an intrusion " +
    "imposes continuous handshake cost during the far longer periods when " +
    "nothing is wrong. Fang et al. [32] applied reinforcement learning to " +
    "adaptive key rotation in Zigbee networks, comparing against periodic, " +
    "anomaly triggered, heuristic and static strategies, and reported " +
    "improvements across intrusion detection and response measures. That work " +
    "is the closest prior art to the controller presented here, and we " +
    "position our contribution against it explicitly in Section II-G."));

  B.push(body("Three failure modes recur in deployed key management for this " +
    "sector. Keys outlive their intended period because rotation requires a " +
    "maintenance window that is repeatedly deferred. Rotation is triggered " +
    "manually after an incident, by which time the exposure has already " +
    "occurred. Or rotation is scheduled so conservatively that its cost " +
    "becomes an argument against the security control itself. An adaptive " +
    "policy addresses all three only if it can be trusted to act without " +
    "supervision, which is why the shield described in Section IV-F is not an " +
    "optional refinement but a precondition for deployment."));

  B.push(subsection("D", "Chaotic and Hybrid Stream Constructions"));
  B.push(body("Chaotic maps have been proposed for lightweight encryption [19], [20] " +
    "for three decades, motivated by sensitivity to initial conditions and " +
    "low arithmetic cost. The literature contains a persistent methodological " +
    "weakness: statistical quality is frequently reported at a single " +
    "favourable parameter choice rather than swept across the usable " +
    "parameter space [21], and adaptive variants that adjust parameters in " +
    "response to a risk or threat signal are an established idea rather than " +
    "a new one [22]. Our own first design followed this pattern and failed " +
    "it, " +
    "which Section V-G reports in full."));

  B.push(subsection("E", "Anomaly Detection for Industrial Telemetry"));
  B.push(body("Reconstruction based sequence models [27], [28] are the standard " +
    "approach where labelled attacks are unavailable, and federated " +
    "arrangements [29] address the same scarcity by pooling across sites " +
    "rather than by labelling. This is the normal " +
    "condition for a working installation. The scarce resource in this area " +
    "is not model architecture but labelled data containing benign " +
    "disturbances. Earlier SCADA specific detection combined network and " +
    "process attributes [24]. Datasets that label natural faults separately " +
    "from attacks " +
    "[25], [26] are much rarer than those that do not, and the distinction " +
    "determines whether a reported precision figure describes a useful " +
    "detector or an easy one."));

  B.push(body("A second difficulty is the evaluation convention. Precision " +
    "and recall computed against a negative class consisting only of quiet " +
    "operation measure a much easier problem than the one an operator faces, " +
    "because the realistic negatives are faults, switching transients and " +
    "maintenance activity rather than calm. Reported figures above 0.99 are " +
    "common in this literature and frequently rest on that convention. " +
    "Section V-D reports both conventions for the detector presented here, " +
    "and the gap between them is substantial."));

  B.push(subsection("F", "Learning for Security Decision Making"));
  B.push(body("Reinforcement learning has been applied to intrusion " +
    "response, moving target defence, routing under energy constraints [33] " +
    "and automated attack planning [36]. " +
    "These systems generally assume a detection signal of fixed quality. " +
    "Domain randomisation, developed for transferring robotic policies from " +
    "simulation to physical hardware [34], addresses the analogous problem in " +
    "a different field by randomising simulator parameters so that the " +
    "learned policy does not overfit any single instantiation. We are not " +
    "aware of its application to the quality of a security detector."));

  B.push(subsection("G", "Resilient and Fail-Secure Control Architectures"));
  B.push(body("Fail secure interlocks are long established in industrial " +
    "practice and leases are long established in distributed systems, where " +
    "they bound the period during which a participant may act on stale " +
    "authority. The combination relevant here, in which a cryptographically " +
    "authenticated lease governs a graduated security posture at an edge " +
    "device and expiry escalates that posture without external instruction, " +
    "does not appear to have been reported for industrial telemetry."));

  B.push(subsection("H", "Research Gap and Motivation"));
  B.push(body("Table I summarises the position. Each column is addressed " +
    "individually in the literature and the combination is not. In " +
    "particular, no reviewed system both places post quantum key " +
    "establishment appropriately across a constrained topology and makes key " +
    "lifecycle decisions that remain valid when the detector informing them " +
    "is replaced."));
  B.push(tableCaption("I", "Comparative position of representative approaches"));
  B.push(gridTable(
    [W(0.28), W(0.18), W(0.18), W(0.18), COL_DXA - W(0.28) - W(0.18) - W(0.18) - W(0.18)],
    ["Approach", "PQC root", "Learned rotation", "Detector agnostic", "Fail secure plane"],
    [
      ["IEC 62351 profiles [8]", "partial", "no", "no", "no"],
      ["PQC for constrained IoT [1], [2]", "yes", "no", "no", "no"],
      ["RL key rotation, Zigbee [32]", "no", "yes", "no", "no"],
      ["Chaotic lightweight ciphers", "no", "no", "no", "no"],
      ["ICS anomaly detection [25], [27]", "no", "no", "not applicable", "no"],
      ["This work", "yes", "yes", "yes", "yes"],
    ]));
  B.push(gap(170));

  // ───────────────── III. Proposed system architecture ─────────────────
  B.push(section("III", "Proposed System Architecture"));
  B.push(subsection("A", "Design Principles"));
  B.push(body("Four principles govern the design. Cost is placed where it " +
    "can be absorbed, so expensive primitives run on capable tiers. " +
    "Invariants are enforced below the policy layer, so that a learned " +
    "component cannot violate them whatever it is trained to do. Authority " +
    "expires rather than being revoked, so loss of communication degrades " +
    "toward caution rather than toward trust. And every security relevant " +
    "field is authenticated whether or not it is confidential, so that " +
    "metadata cannot be manipulated independently of payload."));

  B.push(subsection("B", "System Overview"));
  B.push(body("Figure 1 shows the three tiers. Sensor nodes sample five " +
    "channels and transmit COBS framed telemetry over a serial link to a " +
    "field gateway. The gateway aggregates readings into one second windows, " +
    "applies the masking layer, seals the window and forwards it to the " +
    "control server over TCP. The server authenticates and decrypts, scores " +
    "the window, and answers with a sealed control frame carrying a lease " +
    "renewal and a posture directive."));
  B.push(figure("fig1_architecture.png", 300, 96));
  B.push(caption([
    { t: "Figure 1. ", b: true },
    { t: "Three tier architecture. Telemetry flows upward in one second " +
         "windows and sealed control frames return a lease and a posture " +
         "directive. The gateway acts on its own authority when the downward " +
         "path stops.", i: true },
  ]));

  B.push(subsection("C", "Device Layer"));
  B.push(body("Each sensor node samples five channels covering analogue and " +
    "digital sources, converts analogue channels through an external " +
    "converter, and applies plausibility bands that mark each reading with a " +
    "quality flag before transmission. The node holds a provisioned 32 byte " +
    "pre shared key in non volatile storage and refuses to operate without " +
    "it, which makes an unprovisioned or wiped device fail closed rather than " +
    "join the network in an unauthenticated state. Session establishment is " +
    "an X25519 exchange [6] bound to that pre shared key, so neither the " +
    "long term secret nor the ephemeral contribution is sufficient alone."));

  B.push(subsection("D", "Gateway Layer"));
  B.push(body("The gateway is the only tier that participates in both " +
    "cryptographic domains. It terminates node sessions, aggregates telemetry " +
    "into fixed windows, holds the post quantum session with the server, runs " +
    "the key lifecycle controller, and maintains its own local detection " +
    "signals independent of the server. Running local evidence at this tier " +
    "is what allows the gateway to act when the server is unreachable: " +
    "authentication failure rates, replay rejection rates and silent channel " +
    "counts are observations the gateway owns rather than receives."));

  B.push(subsection("E", "Server Layer"));
  B.push(body("The control server maintains per gateway session state, " +
    "performs replay checking against a monotonic sequence window, runs the " +
    "anomaly detector over decrypted windows, and issues leases. It is " +
    "trusted in the threat model of Section IV-A and is deliberately not " +
    "required for continued secure operation of the tiers below it."));

  B.push(subsection("F", "Security Layer"));
  B.push(body("The cryptographic stack is layered so that each mechanism has " +
    "one responsibility. Post quantum encapsulation establishes root keys. " +
    "The derivation function expands a root into per node, per purpose " +
    "session keys. Authenticated encryption provides confidentiality and " +
    "integrity per frame with the header as associated data. The masking " +
    "layer applies posture dependent transformation outside the " +
    "authenticated encryption, so that removing it would not weaken " +
    "confidentiality. Table II lists the responsibilities by tier."));
  B.push(tableCaption("II", "Functional responsibilities by tier"));
  B.push(gridTable(
    [W(0.24), W(0.40), COL_DXA - W(0.24) - W(0.40)],
    ["Tier", "Responsibility", "Key material held"],
    [
      ["Sensor node", "Sampling, quality flags, framing, per frame sealing",
       "Device PSK, one session key"],
      ["Gateway", "Aggregation, masking, policy, local detection, lease state",
       "Node session keys, uplink key pool"],
      ["Server", "Replay check, detection, lease issuance, directives",
       "Per gateway root and control keys"],
    ]));
  B.push(gap(170));

  B.push(subsection("G", "End-to-End Communication Workflow"));
  B.push(body("A complete cycle proceeds as follows. Nodes transmit framed " +
    "readings continuously. At the close of each one second window the " +
    "gateway drains its aggregator, separating trusted channels from any " +
    "currently quarantined ones, which continue to be collected and " +
    "forwarded under an untrusted marking rather than discarded. The window " +
    "is masked, sealed under the current session key with the frame header as " +
    "associated data, and transmitted. The server verifies the replay guard, " +
    "authenticates and decrypts, scores the window, and returns a sealed " +
    "control frame. The gateway validates the control sequence number, adopts " +
    "the directive subject to its shield, renews its lease, and echoes the " +
    "adopted posture in the next outbound header. If no control frame " +
    "arrives before the lease expires, the gateway escalates one posture " +
    "level and re arms, so that a dead control channel walks the ladder " +
    "upward over successive periods rather than either stalling or jumping to " +
    "the top on a single lost packet."));

  B.push(figure("fig5_workflow.png", 268, 690));
  B.push(caption([
    { t: "Figure 2. ", b: true },
    { t: "End to end operational workflow, from node provisioning through " +
         "session establishment, derivation, the sealed telemetry pipeline " +
         "and detection to the posture decision. The two dashed paths are the " +
         "fail secure elements: lease expiry escalates the gateway without " +
         "instruction and never quarantines, and the adopted posture returns " +
         "in the next authenticated header so the server verifies adoption.",
      i: true },
  ]));

  B.push(subsection("H", "Hardware Testbed"));
  B.push(body("The testbed is assembled from low cost commercially available " +
    "embedded hardware rather than industrial grade equipment. The choice is " +
    "deliberate: the claim under test is that the cryptographic and learned " +
    "components remain viable on the class of device that actually populates " +
    "field deployments, and that claim is not supported by demonstrating it " +
    "on capable hardware."));
  B.push(body("The field node is built on an ESP32 DevKit V1, which occupies " +
    "the role a remote terminal unit or intelligent electronic device would " +
    "hold when bolted to a transformer or to switchgear. Three sensors " +
    "attach to it. A ZMPT101B measures AC voltage and stands for the " +
    "potential transformers used to read bus voltage in a real installation. " +
    "An ACS712 measures current and stands for the current transformers. A " +
    "DHT22 supplies temperature and humidity. A five volt relay module acts " +
    "as the physical actuator and can isolate a circuit section when the " +
    "control plane calls for it."));
  B.push(body("An MCP3008 external converter sits between the analogue " +
    "sensors and the microcontroller. The ESP32 has internal converters, but " +
    "they are non linear and noisy enough to degrade electrical telemetry, " +
    "so the MCP3008 digitises the analogue channels and delivers clean values " +
    "over SPI: the microcontroller pulls chip select low, clocks three bits " +
    "out on MOSI to choose the channel, and reads the ten bit result back on " +
    "MISO. The node aggregates all readings into a structured payload and " +
    "transmits it over UART at 115200 baud. The link is asynchronous so that " +
    "transmission never blocks the sampling loop, which runs at " +
    "approximately 10 Hz."));
  B.push(body("The gateway runs on a Raspberry Pi 4B and acts as the " +
    "substation gateway, the intermediate node that field devices report to " +
    "rather than connecting to a control centre directly. Its ARM processor " +
    "absorbs the work the node cannot: the ML-KEM-512 and ML-DSA-44 " +
    "handshake with the server, RXCR-KMAC-KDF derivation, AES-256-GCM " +
    "sealing and ACCM masking of outbound telemetry, and the learned key " +
    "lifecycle controller together with the local fast path signals of " +
    "Section III-D. The LSTM detector runs on the control server, which " +
    "receives the sealed telemetry over TCP. The whole testbed draws from a " +
    "regulated bench supply, and the wiring is shown in Figure 3."));
  B.push(figure("fig6_hardware.png", 300, 187));
  B.push(caption([
    { t: "Figure 3. ", b: true },
    { t: "Testbed wiring. The ESP32 field node reads the voltage, current " +
         "and environmental sensors through the MCP3008 converter and drives " +
         "the relay; the Raspberry Pi 4B gateway performs the post quantum " +
         "handshake, derivation, sealing and masking, and runs the learned " +
         "controller.", i: true },
  ]));

  // ───────────────── IV. Implementation and security ─────────────────
  B.push(section("IV", "Implementation and Security"));

  B.push(subsection("A", "Threat Model"));
  B.push(body("We assume an adversary able to observe and record all traffic " +
    "on the gateway to server link indefinitely, inject and replay frames on " +
    "either link, disrupt the control channel at will, and compromise an " +
    "individual sensor node including its provisioned key material. We do not " +
    "assume compromise of the control server or physical extraction from the " +
    "gateway secure storage. Node compromise is contained rather than " +
    "prevented: a node holds only its own session key and its own pre shared " +
    "key, so a compromised node can corrupt its own channel and no other, " +
    "which is the property that makes per channel quarantine meaningful."));

  B.push(subsection("B", "Post-Quantum Root Establishment"));
  B.push(body("The server generates an ML-KEM-512 keypair per gateway epoch " +
    "and signs the public key with ML-DSA-44. The gateway verifies the " +
    "signature, encapsulates, and both sides derive a root key from the " +
    "shared secret together with a transcript hash binding the exchange. " +
    "Level 1 and level 2 parameter sets are selected for the constrained " +
    "deployment and are revisited in Section VI as a deployment decision " +
    "rather than presented as a recommendation."));

  B.push(subsection("C", "Key Derivation"));
  B.push(body("Session keys derive through an extract and expand construction " +
    "following the paradigm established by HKDF [5]. The extraction stage " +
    "applies a positional rotate and mix pre mix over the input keying " +
    "material before a SHA3-256 finalizer; the expansion stage is KMACXOF256 " +
    "[4] domain separated per node and per purpose [18], so that a single pass " +
    "produces the telemetry key, the control key and the masking seed for " +
    "every node in the pool. Because the finalizer consumes the input keying " +
    "material and salt directly, the derived key is at least as strong as " +
    "SHA3-256 over the same inputs irrespective of the pre mix. We state this " +
    "as a fail safe floor and not as a novelty claim: it is the standard " +
    "argument for extract then expand, and our measurements do not show the " +
    "pre mix contributing beyond it."));

  B.push(subsection("D", "Authenticated Encryption and Nonce Discipline"));
  B.push(body("Frames are sealed with AES-256-GCM [3] under a 96 bit nonce " +
    "formed as the four byte key epoch concatenated with the eight byte " +
    "sequence number. Uniqueness is structural: the epoch increases on every " +
    "rotation and the sequence counter never repeats within an epoch, so no " +
    "key and nonce pair can recur even across an unclean restart, and the " +
    "sensor node is never required to produce randomness. A guard forces " +
    "rotation before sequence exhaustion, and that guard is implemented below " +
    "the policy layer so that no learned decision can violate the invariant."));

  B.push(subsection("E", "Adaptive Chaotic Masking"));
  B.push(body("An adaptive coupled chaotic map masks ciphertext on the " +
    "gateway to server link with coupling strength driven by the current " +
    "posture. Each frame re derives its parameters from the session key, the " +
    "authenticated frame header and the previous frame keystream tail, " +
    "producing a chain of short independently seeded streams bound to the " +
    "frame sequence. The chaotic byte is combined with a KMACXOF256 base " +
    "stream rather than used alone, following the measurement reported in " +
    "Section V-G. The resulting layer provides posture dependent traffic " +
    "shaping and defence in depth; it is explicitly not relied upon as a " +
    "source of entropy, and it sits outside the authenticated encryption so " +
    "that the channel security argument is unchanged by its presence."));

  B.push(subsection("F", "Learned Key Lifecycle Controller"));
  B.push(body("The controller observes 20 features in five groups: threat " +
    "signals including the calibrated detector score and its fast and slow " +
    "moving averages; control plane state including lease remaining and the " +
    "directive floor; key lifecycle state including sequence consumption, key " +
    "age and bytes under the current key; local fast path evidence; and " +
    "resource state. Eight actions are available, spanning hold, three " +
    "rotation scopes, posture escalation and de escalation, channel " +
    "quarantine, and an immediate detector flush that spends bandwidth to " +
    "shorten detection lag for one step."));
  B.push(body("The agent is a duelling double deep Q network [30], [31] with " +
    "five step returns. Three design decisions matter more than the " +
    "architecture. A safety shield makes unsafe actions unreachable rather " +
    "than penalised, bounding rotation rate, enforcing minimum posture hold " +
    "times and forcing rotation before nonce exhaustion. The reward charges " +
    "for exposure and for action, with action costs taken from measurements " +
    "of the implementation and false positives charged separately from " +
    "rotations. And every training episode draws a different detector quality " +
    "from a grid over false positive rate, false negative rate and detection " +
    "delay, which is the mechanism that makes the policy transferable."));

  B.push(subsection("G", "Anomaly Detection"));
  B.push(body("The detector is a long short term memory autoencoder [27] " +
    "trained on benign windows only, because a healthy installation produces " +
    "no labelled attacks. Reconstruction error is converted to a calibrated " +
    "score by the empirical cumulative distribution function of error over " +
    "held out benign data, so that a score of 0.99 means worse than 99 " +
    "percent of benign windows. Per feature error supplies channel " +
    "attribution, which the quarantine mechanism requires: a detector " +
    "reporting only that something is wrong cannot drive isolation of a " +
    "specific instrument."));

  B.push(subsection("H", "Posture State Machine and Shield Rules"));
  B.push(body("The posture ladder has four levels. Normal is the steady " +
    "state. Suspicious tightens reporting and shortens the detector flush " +
    "interval. Anomaly additionally constrains which actions the policy may " +
    "take and raises the rotation priority. Quarantine marks named channels " +
    "untrusted while continuing to ingest them, so that the data remains " +
    "available for triage rather than being destroyed by the response."));
  B.push(body("Three directive kinds travel on the control channel. An " +
    "advise directive carries the server assessment and may be weighed by the " +
    "gateway against its own evidence. An enforce directive sets a floor " +
    "below which the local policy may not descend. A quarantine directive is " +
    "mandatory, carries a channel bitmap, and forces the anomaly posture. " +
    "Quarantine masks accumulate rather than replace, so that two overlapping " +
    "detections cannot clear one another, and release is an explicit triage " +
    "action at both ends rather than a timeout."));
  B.push(body("The shield enforces four invariants independently of the " +
    "learned policy. Rotation is rate limited so that a policy cannot consume " +
    "the key pool. A minimum hold time applies before any de escalation, " +
    "which prevents oscillation around a detection threshold. De escalation " +
    "below a server imposed floor is refused. And rotation is forced when " +
    "sequence consumption approaches the nonce limit, which places the " +
    "uniqueness invariant of Section IV-D below the policy layer entirely. " +
    "Because these are implemented as action masking rather than as reward " +
    "penalties, no training outcome can violate them."));

  B.push(subsection("I", "Implementation Parameters"));
  B.push(tableCaption("III", "System implementation specifications"));
  B.push(gridTable(
    [W(0.46), COL_DXA - W(0.46)],
    ["Parameter", "Value"],
    [
      ["Key encapsulation", "ML-KEM-512"],
      ["Signature", "ML-DSA-44"],
      ["Node key agreement", "X25519 with device PSK"],
      ["Authenticated encryption", "AES-256-GCM"],
      ["Nonce", "96 bit, epoch and sequence"],
      ["Key derivation", "Rotate-mix, SHA3-256, KMACXOF256"],
      ["Aggregation window", "1 s"],
      ["Sensor channels per node", "5"],
      ["Controller", "Duelling double DQN, 5 step returns"],
      ["Observation and action space", "20 features, 8 actions"],
      ["Training", "5000 episodes, 3 seeds"],
      ["Detector", "LSTM autoencoder, 60 step window"],
      ["Detector calibration", "Empirical CDF on held out benign"],
    ]));
  B.push(gap(170));

  // ───────────────── V. Results and analysis ─────────────────
  B.push(section("V", "Results and Implementation Analysis"));

  B.push(subsection("A", "Evaluation Protocol"));
  B.push(body("Policies are compared on identical episodes and differenced " +
    "per seed, because most of the variance between episodes is attributable " +
    "to the episode rather than the policy: an episode containing a long " +
    "intrusion is unfavourable for every policy. Differencing cancels that " +
    "shared difficulty. All reported intervals are 95 percent confidence " +
    "intervals on the paired difference. Model selection uses held out " +
    "episodes disjoint from those used for any reported figure."));

  B.push(subsection("B", "Key Lifecycle Controller"));
  B.push(tableCaption("IV", "Key lifecycle policies, 15 seeds, 4 episodes of 600 steps"));
  B.push(gridTable(
    [W(0.30), W(0.18), W(0.19), W(0.17), COL_DXA - W(0.30) - W(0.18) - W(0.19) - W(0.17)],
    ["Policy", "Return", "Comprom.", "Rotations", "False pos."],
    [
      ["Learned (proposed)", "-435.8", "19.3", "12.9", "7.0"],
      ["Oracle reference", "-677.5", "5.3", "5.0", "173.7"],
      ["Threshold", "-1610.9", "75.6", "53.9", "12.8"],
      ["Always maximum", "-3481.8", "91.8", "60.0", "507.2"],
      ["Never rotate", "-3723.0", "177.4", "0.0", "24.8"],
      ["Fixed interval", "-3946.3", "191.1", "2.0", "24.8"],
    ]));
  B.push(gap(170));
  B.push(body("The oracle observes the hidden compromise state and is a " +
    "perfect information reference rather than an upper bound: it escalates " +
    "whenever an adversary is present and pays heavily in false positives, " +
    "which is why a policy with strictly less information scores above it. " +
    "The learned policy beats the threshold rule by 1175.1 with a 95 percent " +
    "confidence interval of 600.8 to 1749.3, winning on 15 of 15 seeds."));
  B.push(body("The most operationally meaningful figure is not the return but " +
    "the rotation count. The learned controller achieves 74 percent fewer " +
    "compromised steps using 76 percent fewer key rotations than the " +
    "threshold rule. Protection is obtained through better timing rather than " +
    "greater activity, which matters because each rotation propagates a " +
    "handshake across the fleet and is the cost an operator actually bears."));
  B.push(figure("fig2_training.png", 300, 256));
  B.push(caption([
    { t: "Figure 4. ", b: true },
    { t: "Training across three seeds, smoothed over 100 episodes. Returns " +
         "improve throughout and compromised steps fall substantially. The " +
         "spread between seeds is the reason model selection uses held out " +
         "episodes rather than the training curve.", i: true },
  ]));

  B.push(subsection("C", "Transfer Across Detector Quality"));
  B.push(body("Figure 5 plots the learned policy against the threshold rule " +
    "at each of the 27 points of the detector grid. Every point lies above " +
    "parity, so the policy wins at every combination of false positive rate, " +
    "false negative rate and detection delay tested, and the margin widens as " +
    "the detector degrades. The policy additionally wins all nine settings of " +
    "a disturbance regime introduced after the detector had been measured, in " +
    "which the detector false alarms continuously throughout benign grid " +
    "faults. That regime lies outside the training distribution entirely and " +
    "the policy was not retrained for it."));
  B.push(figure("fig3_robustness.png", 300, 185));
  B.push(caption([
    { t: "Figure 5. ", b: true },
    { t: "Robustness across the 27 point detector grid. All points lie above " +
         "the parity line.", i: true },
  ]));

  B.push(body("Table V reports the disturbance regime in full. Each row " +
    "fixes a rate at which benign grid faults occur and a detection delay, " +
    "with the detector false alarming continuously for the duration of each " +
    "fault. The paired advantage over the threshold rule is positive and " +
    "statistically separable at every setting."));
  B.push(tableCaption("V", "Disturbance regime, paired advantage over threshold"));
  B.push(gridTable(
    [W(0.22), W(0.18), W(0.30), COL_DXA - W(0.22) - W(0.18) - W(0.30)],
    ["Fault rate", "Delay", "Advantage", "Seeds won"],
    [
      ["0.01", "1", "+1362", "8 of 8"],
      ["0.01", "3", "+1402", "8 of 8"],
      ["0.01", "6", "+1438", "8 of 8"],
      ["0.03", "1", "+1308", "8 of 8"],
      ["0.03", "3", "+1683", "8 of 8"],
      ["0.03", "6", "+1330", "8 of 8"],
      ["0.06", "1", "+1748", "8 of 8"],
      ["0.06", "3", "+2071", "7 of 8"],
      ["0.06", "6", "+1525", "8 of 8"],
    ]));
  B.push(gap(170));

  B.push(subsection("D", "Anomaly Detector"));
  B.push(tableCaption("VI", "Detector performance, 55 held out sequences"));
  B.push(gridTable(
    [W(0.44), W(0.30), COL_DXA - W(0.44) - W(0.30)],
    ["Measure", "Operational", "vs calm grid"],
    [
      ["Average precision", "0.964", "0.999"],
      ["Recall on attacks", "0.96 to 0.98", ""],
      ["Median detection delay", "0.03 s", ""],
      ["Inference per window", "2.5 ms", ""],
      ["False alarms on faults", "0.98 to 1.00", ""],
    ]));
  B.push(gap(170));
  B.push(body("The operational column counts natural disturbances as " +
    "negatives, which is the question an operator asks, since a fault that " +
    "raises an attack alarm is a false alarm whatever the underlying physics. " +
    "The second column excludes them and is correspondingly flattering. Per " +
    "scenario recall has a median of 1.000 across the 28 attack types, and " +
    "the two weakest scenarios are both line maintenance with relays " +
    "disabled, so the attacks hardest to detect are those resembling routine " +
    "engineering work."));
  B.push(body("The false alarm rate on natural disturbances is a genuine " +
    "negative result. Reconstruction error measures the unusual, and a fault " +
    "is extremely unusual, so the mechanism that detects attacks is the one " +
    "that responds to weather. We therefore describe this component as a " +
    "disturbance detector rather than an attack detector and locate the " +
    "discrimination in the policy that consumes its output. The architecture " +
    "was built for a detector that is frequently wrong: the score is " +
    "calibrated input to a policy rather than a verdict, the policy is " +
    "trained with an explicit false positive cost, and the response to " +
    "suspicion is to isolate and continue rather than to halt."));

  B.push(body("Table VII gives the per scenario breakdown. Detection is " +
    "essentially complete for the command injection and relay disabling " +
    "families. The two weak scenarios, 39 and 40, are both line maintenance " +
    "performed with relays disabled, and they are weak for an intelligible " +
    "reason: the attack consists of performing a legitimate maintenance " +
    "operation under conditions that make it dangerous, so the telemetry it " +
    "produces closely resembles authorised work. An adversary who understands " +
    "the plant is harder to detect than one who does not, which is a result " +
    "worth stating plainly rather than averaging away."));
  B.push(tableCaption("VII", "Per scenario detection recall, 28 attack types"));
  B.push(gridTable(
    [W(0.17), W(0.16), W(0.17), W(0.16), W(0.17), COL_DXA - W(0.17) - W(0.16) - W(0.17) - W(0.16) - W(0.17)],
    ["Scn", "Recall", "Scn", "Recall", "Scn", "Recall"],
    [
      ["7", "1.000", "19", "1.000", "29", "1.000"],
      ["8", "1.000", "20", "1.000", "30", "0.987"],
      ["9", "1.000", "21", "1.000", "35", "0.976"],
      ["10", "1.000", "22", "1.000", "36", "0.998"],
      ["11", "1.000", "23", "0.985", "37", "1.000"],
      ["12", "0.976", "24", "1.000", "38", "1.000"],
      ["15", "1.000", "25", "1.000", "39", "0.791"],
      ["16", "1.000", "26", "0.995", "40", "0.465"],
      ["17", "1.000", "27", "1.000", "", ""],
      ["18", "1.000", "28", "1.000", "", ""],
    ]));
  B.push(gap(170));
  B.push(body("The eight natural disturbance scenarios are the mirror image. " +
    "Every one produces a false alarm rate between 0.997 and 1.000, so the " +
    "detector responds to all of them as though they were attacks. The " +
    "uniformity of that result across scenario types is itself informative: " +
    "this is not a tuning deficiency affecting some fault classes but a " +
    "property of reconstruction error as a signal."));

  B.push(subsection("E", "Integrated Behaviour and Timing"));
  B.push(body("The integrated system passes 24 of 24 behavioural checks " +
    "across four scenarios: normal operation with the lease renewing; an " +
    "injected attack driving escalation with the posture echo verified; loss " +
    "of the control channel, in which the gateway escalates unaided while " +
    "telemetry continues to flow and no channel is quarantined; and " +
    "quarantine of a single channel followed by recovery, triage and release. " +
    "The 95th percentile cycle time is 41 ms against a one second budget, and " +
    "detector inference accounts for 2.5 ms of that."));

  B.push(subsection("F", "Hardware Characterisation"));
  B.push(body([
    { t: "The figures in Table VIII are " },
    { t: "placeholders", i: true, b: true },
    { t: ". Firmware is complete and host tested and bring-up of the sensor " +
         "node and gateway hardware is scheduled, but these measurements have " +
         "not yet been taken. Values are consistent with the target platforms " +
         "and with host measurements, and are included so that the structure " +
         "of the completed evaluation is visible. Each must be replaced " +
         "before this table is cited." },
  ]));
  B.push(tableCaption("VIII", "Hardware characterisation (PLACEHOLDER, pending bring-up)"));
  B.push(gridTable(
    [W(0.50), W(0.24), COL_DXA - W(0.50) - W(0.24)],
    ["Quantity", "Value", "Status"],
    [
      ["AES-256-GCM seal, 64 B frame", "0.12 ms", "placeholder"],
      ["X25519 exchange, sensor node", "31 ms", "placeholder"],
      ["ML-KEM-512 encapsulation, gateway", "0.09 ms", "placeholder"],
      ["ML-DSA-44 verification, gateway", "0.31 ms", "placeholder"],
      ["Serial frame transmission", "7.03 ms", "measured, host"],
      ["Firmware image", "182 KB", "placeholder"],
      ["Peak RAM, sensor node", "42 KB", "placeholder"],
      ["Soak, 1 h at 10 Hz, auth failures", "0", "placeholder"],
    ]));
  B.push(gap(170));
  B.push(body("The single measured row is informative on its own. Sealing a " +
    "frame costs 0.019 ms on the host against 7.03 ms of serial " +
    "transmission, so the link and not the cryptography determines the " +
    "achievable sampling rate. We expect this ratio to narrow but not to " +
    "invert on the target hardware, which would contradict the common " +
    "assumption that cryptography is the limiting cost on constrained " +
    "devices. Confirming or refuting that is the first measurement scheduled " +
    "at bring-up."));

  B.push(subsection("G", "Negative Results"));
  B.push(body("Five measurement failures occurred during development, each " +
    "producing a plausible but incorrect result until checked. We report them " +
    "because the corrective procedure is inexpensive in every case and three " +
    "generalise beyond this system."));
  B.push(body([
    { t: "1) Chaos only keystream. ", b: true },
    { t: "The initial masking design generated its keystream from coupled " +
         "logistic maps alone. Across the parameter space, 100 percent of " +
         "draws fell below 7.99 bits per byte, and at a coupling strength of " +
         "0.4 the stream measured 3.26 bits per byte with a single value " +
         "occupying 36 percent of output. The cause is synchronisation: " +
         "coupling drives the maps toward a common trajectory and combining " +
         "the same bit slice of two synchronised states collapses it. The " +
         "deployed hybrid measures 7.99995 bits per byte at every posture. A " +
         "single favourable parameter choice would have passed, which is why " +
         "we report the sweep." },
  ]));
  B.push(figure("fig7_bifurcation.png", 300, 213));
  B.push(caption([
    { t: "Figure 6. ", b: true },
    { t: "Bifurcation of the coupled map against coupling strength, with the " +
         "normal and anomaly operating points marked. The structure is rich " +
         "across the range, which is precisely why a single favourable " +
         "parameter choice is misleading: at the anomaly coupling the " +
         "chaos only stream still measured 3.26 bits per byte.", i: true },
  ]));
  B.push(figure("fig4_scores.png", 300, 172));
  B.push(caption([
    { t: "Figure 7. ", b: true },
    { t: "Measured detector score distributions against the distribution the " +
         "controller was trained to expect. Calibration forces benign scores " +
         "to be uniform while the surrogate assumed mass near zero. Attacks " +
         "and natural disturbances both concentrate near unity.", i: true },
  ]));

  B.push(body([
    { t: "2) Contradictory calibration contract. ", b: true },
    { t: "The controller trained against a surrogate whose benign scores were " +
         "drawn from a Beta(1.5, 6) distribution with mean 0.20. Empirical " +
         "distribution calibration, however, forces benign scores to be " +
         "uniform by construction, and the trained detector measured mean " +
         "0.503. Both components were written to the same specification and " +
         "contradicted one another, as Figure 7 shows. The consequence " +
         "appeared only when both trained components were connected: on calm " +
         "traffic the hold action collapsed from 60.1 percent of steps in " +
         "simulation to 5 percent in the integrated system, and rotation rose " +
         "from 7.0 percent to 42 percent. Re fitting the surrogate and " +
         "retraining restored the behaviour and improved every metric in " +
         "Table IV." },
  ]));
  B.push(body([
    { t: "3) Statistical testing without a control. ", b: true },
    { t: "Running the SP 800-22 battery [7] against a cryptographically " +
         "secure generator alongside the primitives under test, six of twelve " +
         "tests failed on that known good input at 100,000 bit sequences. " +
         "Without the control, the reported headline would have been that the " +
         "key derivation function fails half the battery. Excluding the tests " +
         "the control cannot pass, the extractor matches the control test for " +
         "test across the battery." },
  ]));
  B.push(body([
    { t: "4) Model selection on insufficient data. ", b: true },
    { t: "Training retained the best weights by evaluation on three held out " +
         "episodes. One episode scored almost identically for every candidate " +
         "and carried no information, so the ranking rested on essentially one " +
         "episode, and re ranking on 15 episodes reversed the winner. " +
         "Selection on three episodes proved measurably worse than no " +
         "selection at all." },
  ]));
  B.push(body([
    { t: "5) An unfalsifiable safety criterion. ", b: true },
    { t: "The acceptance criterion for nonce safety was zero exhaustion " +
         "events, and the evaluation reported zero forced rotations. At the " +
         "episode length used, the guard rail could not be reached even by a " +
         "policy that never rotated, so a do nothing agent would have scored " +
         "identically. Re run at a length where the threshold is reachable, " +
         "the result holds, with peak sequence consumption two orders of " +
         "magnitude below the limit." },
  ]));

  // ───────────────── VI. Conclusion ─────────────────
  B.push(section("VI", "Discussion"));
  B.push(subsection("A", "Where the Advantage Comes From"));
  B.push(body("The learned controller does not rotate more often than the " +
    "threshold rule; it rotates roughly a quarter as often. Its advantage is " +
    "therefore not additional activity but timing, and inspecting the policy " +
    "shows where that timing comes from. The controller conditions on the " +
    "rate of change of the detector score rather than on its level alone, on " +
    "local evidence the gateway owns such as authentication failure rates, " +
    "and on how long the current key has been in service. A threshold rule " +
    "has access to none of this and must commit on a single scalar crossing a " +
    "line."));
  B.push(subsection("B", "Why the Detector Failure Is Tolerable"));
  B.push(body("A detector that raises an alarm on essentially every natural " +
    "disturbance would be unusable as a trigger. It is usable as evidence " +
    "because the architecture never treats it as a trigger. The score enters " +
    "a policy that was trained knowing the detector is frequently wrong, the " +
    "response to suspicion preserves data flow, and quarantine requires " +
    "explicit triage to release rather than resolving itself. The " +
    "quantitative requirement is that the false alarm rate be known, not that " +
    "it be low, and Section V-D supplies the measurement."));
  B.push(subsection("C", "Limitations"));
  B.push(body("The hardware characterisation in Table VIII is composed of " +
    "placeholders and must be replaced before publication. The detector " +
    "deployed in the integrated harness is trained on synthetic benign " +
    "traffic, because the public corpus features do not transfer to a five " +
    "channel installation: the public data earns the detection numbers and " +
    "the harness demonstrates the control path, and neither substitutes for " +
    "the other. Channel attribution accuracy is unmeasurable on the public " +
    "corpus, whose labels name scenarios rather than manipulated instruments. " +
    "The statistical battery of Section V-G is a necessary and not a " +
    "sufficient condition. The forced rotation path of the shield is never " +
    "exercised by the trained policy, whose own cadence keeps sequence " +
    "consumption far below the guard rail, so that path rests on unit tests. " +
    "And the level 1 and level 2 parameter sets are a deployment decision to " +
    "revisit rather than a recommendation."));

  B.push(section("VII", "Conclusion and Future Work"));
  B.push(body("This paper presented a three tier industrial telemetry " +
    "architecture combining post quantum root establishment placed " +
    "appropriately across a constrained topology, a learned key lifecycle " +
    "controller trained against a distribution of detector qualities, " +
    "posture adaptive masking applied outside the authenticated encryption, " +
    "and a lease based control plane in which authority expires rather than " +
    "being commanded. The controller leaves 74 percent less time under " +
    "adversary control while performing 76 percent fewer key rotations than a " +
    "threshold rule, wins at all 27 detector settings tested, and continues " +
    "to win in a regime outside its training distribution. The integrated " +
    "system passes 24 of 24 behavioural checks within a 41 ms cycle time."));
  B.push(body("Four directions follow. Collecting benign telemetry from the " +
    "instrumented installation and retraining the detector on it converts the " +
    "method demonstrated here into a deployable component and requires no " +
    "labelled attacks. Adding a standing cost for time spent above normal " +
    "posture should remove a degenerate behaviour observed in two of three " +
    "training seeds. Modelling the detector two distinct false positive " +
    "rates, approximately 0.05 on a calm grid and close to unity during a " +
    "fault, would allow the controller to condition on whether the grid is " +
    "disturbed. And signing the gateway encapsulation key with its existing " +
    "signature key, then rotating that keypair per epoch, closes an implicit " +
    "trust assumption and adds forward secrecy to the root transfer."));
  B.push(body("The engineering observation we would emphasise is that two " +
    "components built to a single specification can disagree about what a " +
    "number means, and that no amount of testing within either component " +
    "reveals it. The error surfaced only on connecting both trained models " +
    "and measuring the output. We recommend an explicit interface measurement " +
    "step wherever a learned controller consumes a learned signal, a control " +
    "corpus alongside any statistical randomness result, and a check that " +
    "each safety criterion could have failed within the window in which it " +
    "was measured."));

  B.push(section(null, "Acknowledgment"));
  B.push(body("The authors thank the maintainers of the Mississippi State " +
    "University and Oak Ridge National Laboratory power system attack " +
    "datasets, recovered for this work from the Internet Archive after the " +
    "original host became unavailable."));

  return B;
};
