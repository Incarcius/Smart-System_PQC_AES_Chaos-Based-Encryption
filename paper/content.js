// Paper content, kept apart from the layout helpers in make_docx.js.
//
// House rule: no em dashes and no en dashes anywhere. Clauses that would take
// a dash use a comma, a semicolon, a colon or parentheses. Numeric ranges use
// "to" or a plain hyphen, and negative numbers in tables use a plain hyphen.
//
// PLACEHOLDER POLICY. Hardware bring-up is scheduled but not complete. Every
// hardware figure in Table VI is a realistic placeholder and is labelled as
// such in the table title, in the table itself, and in the surrounding prose.
// They are there so the guide can see the shape of the finished paper. They
// must be replaced with measurements before submission anywhere.

module.exports = function content(API) {
  const { body, section, subsection, caption, tableHead, tableSub, ieeeTable,
          gap, figure, COL_DXA } = API;
  const B = [];
  const W = (frac) => Math.round(COL_DXA * frac);

  // ───────────────────────── I. Introduction ─────────────────────────
  B.push(section("I", "Introduction"));
  B.push(body("Electrical transmission telemetry has an unusual threat " +
    "profile. Individual measurements are of little value, while the aggregate " +
    "is decisive. Equipment lifetimes are measured in decades, so traffic " +
    "captured today is plausibly within reach of an adversary who acquires " +
    "quantum capability before the hardware is retired. And the 2015 Ukrainian " +
    "distribution attack established that a capable adversary will attack the " +
    "operator's visibility alongside the plant itself [7].", { noIndent: true }));
  B.push(body("That last point shapes this work. A design in which the control " +
    "server decides everything fails at exactly the moment the server is the " +
    "component that has been cut off. We therefore place authority in a lease. " +
    "The gateway holds a time limited grant and escalates its own security " +
    "posture when renewals stop arriving, so that silence becomes evidence " +
    "rather than the absence of evidence."));
  B.push(body("The second difficulty is that the quantity a key management " +
    "policy most wants to know, whether an adversary currently holds a live " +
    "key, is never observable. What is available is an anomaly score of unknown " +
    "quality. A policy tuned to one detector is tuned to that detector's " +
    "particular errors, and the detector is usually the component that changes " +
    "last and most. We train against a distribution of detector qualities " +
    "instead of a fixed detector, and we report how far the resulting policy " +
    "transfers."));

  // ─────────────────── II. Threat model and related work ───────────────────
  B.push(section("II", "Threat Model and Related Work"));
  B.push(subsection("A", "Adversary"));
  B.push(body("We assume an adversary who can observe and record all traffic " +
    "on the gateway to server link indefinitely, inject and replay frames on " +
    "either link, disrupt the control channel at will, and compromise an " +
    "individual sensor node including its provisioned key material. We do not " +
    "assume compromise of the control server that issues leases, nor physical " +
    "access to the gateway's secure storage.", { noIndent: true }));
  B.push(body("Two consequences shape the design. Recording today and " +
    "decrypting later is the reason the root exchange is post quantum while the " +
    "per frame work stays symmetric: confidentiality must outlive the hardware, " +
    "but the sensor node cannot afford lattice arithmetic on every reading. " +
    "Disrupting the control channel is the reason authority is leased rather " +
    "than commanded: an adversary who silences the server must not thereby " +
    "silence the defence."));
  B.push(body("Node compromise is contained rather than prevented. A node " +
    "holds only its own session key and a pre shared key bound to its identity, " +
    "so a compromised node can corrupt its own channel and no other. That is " +
    "what makes per channel quarantine a meaningful response rather than a " +
    "gesture."));

  B.push(subsection("B", "Related work"));
  B.push(body("Post quantum key establishment for constrained industrial " +
    "devices is well surveyed, and the standardised lattice schemes [1], [2] " +
    "are now the obvious starting point. Our contribution is not the primitives " +
    "but where their cost is placed in a three tier topology, and the " +
    "observation that the expensive exchange need not reach the most " +
    "constrained tier at all.", { noIndent: true }));
  B.push(body("Reinforcement learning has been applied to intrusion response " +
    "and to moving target defence, generally assuming a detector of fixed " +
    "quality. Training across a distribution of detector qualities, and " +
    "reporting the resulting transfer rather than a single operating point, is " +
    "the methodological departure we argue for."));
  B.push(body("Chaotic stream ciphers are a large literature with a persistent " +
    "methodological weakness: entropy is frequently reported at a single " +
    "favourable parameter choice rather than swept across the space. Our own " +
    "first design passed at its nominal parameters and failed almost everywhere " +
    "else, which is reported in Section XI-A. For anomaly detection in " +
    "industrial telemetry, reconstruction based sequence models [12] are " +
    "standard, and datasets that include labelled natural disturbances [3], " +
    "[10] are much rarer than those that do not."));

  // ───────────────────── III. Novelty and contributions ─────────────────────
  B.push(section("III", "Novelty and Contributions"));
  B.push(body("We searched the literature for each element of this system " +
    "before claiming it, and two of our four candidate contributions did not " +
    "survive that check. We report the outcome in full, because a novelty " +
    "claim that collapses under a reviewer first search costs more than it " +
    "ever gains.", { noIndent: true }));

  B.push(subsection("A", "What we do not claim as novel"));
  B.push(body("The key derivation follows the extract and expand paradigm " +
    "established by HKDF [13]. Our construction substitutes a positional " +
    "rotate and mix pre mix and a SHA3-256 finalizer for the HMAC extractor, " +
    "and expands with KMACXOF256 [9] domain separated per node and per " +
    "purpose. The property that the output is at least as strong as the " +
    "finalizer over the same inputs is the standard argument for extract then " +
    "expand, not a new one, and our own measurements show the pre mix adds " +
    "nothing provable on top of it. We present the design as an engineering " +
    "choice with a documented fail safe floor, and nothing more.",
    { noIndent: true }));
  B.push(body("Adaptive chaotic encryption whose parameters respond to a risk " +
    "or threat signal is likewise an established idea. Driving coupling " +
    "strength from a posture ladder is a reasonable instance of it and is not " +
    "a contribution in itself. What we offer around this component is the " +
    "measurement in Section XI-A, which we believe is more useful to the field " +
    "than another construction would be."));
  B.push(body("Reinforcement learning applied to key rotation is also prior " +
    "work. Fang et al. [14] learn an adaptive key rotation policy for Zigbee " +
    "networks and compare it against periodic, anomaly triggered, heuristic " +
    "and static rotation, which is close in both problem and baseline set to " +
    "the comparison in Table II. Our agent differs in what it is trained " +
    "against rather than in that it is trained at all."));

  B.push(subsection("B", "Detector agnostic policy training"));
  B.push(body("Our first claim is narrow and we think defensible. Where prior " +
    "work learns a rotation policy against a detector, we randomise the " +
    "detector quality every episode across a grid of false positive rate, " +
    "false negative rate and detection delay, so that the policy is fitted to " +
    "the underlying tradeoff rather than to one detector particular errors. " +
    "Domain randomisation is a well established technique for simulation to " +
    "reality transfer in robotics; we are not aware of its use to make a " +
    "security control policy independent of the detector it consumes.",
    { noIndent: true }));
  B.push(body("The evidence is Fig. 3 and the disturbance sweep: the policy " +
    "wins at all 27 points of the detector grid, and at all nine settings of a " +
    "regime introduced after the detector was measured and lying outside the " +
    "training grid entirely. This matters practically because the detector is " +
    "typically the component that changes last and most, and a policy that " +
    "must be retrained whenever the detector is retuned is a policy that will " +
    "not be maintained."));

  B.push(subsection("C", "A lease based fail secure control plane"));
  B.push(body("Our second claim is the alerting path, and it is the one we " +
    "found no prior work for. Leases are long established in distributed " +
    "systems and fail secure interlocks are old in industrial practice, but we " +
    "did not find the combination used here: a cryptographically sealed lease " +
    "whose expiry drives a graduated security posture ladder at the gateway, " +
    "with the adopted posture echoed in the next authenticated frame header so " +
    "the server verifies adoption rather than assuming it, and with expiry " +
    "deliberately never setting the quarantine bitmap.", { noIndent: true }));
  B.push(body("That last property is the design point we would most like to " +
    "see adopted elsewhere. Automatic isolation on a lost control channel is " +
    "the intuitive response and it hands the adversary a denial of service for " +
    "the price of jamming. Escalating posture while continuing to carry " +
    "telemetry inverts that: the adversary who silences the server makes the " +
    "gateway more suspicious rather than less capable, and gains nothing by " +
    "doing it."));

  B.push(subsection("D", "Methodological contributions"));
  B.push(body("Our third contribution is Section XI. Five measurement failures " +
    "are reported in full, and three generalise past this system: a learned " +
    "controller and a learned detector built to one specification can " +
    "contradict each other in a way neither can detect alone; a statistical " +
    "randomness battery needs a known good control corpus at the sequence " +
    "length actually used; and a safety criterion that could not have failed " +
    "in the window it was measured in has not been measured. Each is cheap to " +
    "check and each produced a plausible wrong answer here before it was " +
    "checked.", { noIndent: true }));

  // ───────────────────── IV. System architecture ─────────────────────
  B.push(section("IV", "System Architecture"));
  B.push(body("The system has three tiers, shown in Fig. 1. Sensor nodes " +
    "sample five channels and send COBS framed telemetry over a serial link to " +
    "a field gateway. The gateway aggregates readings into one second windows, " +
    "masks and encrypts them, and forwards them to the control server over TCP. " +
    "The server decrypts, scores the window, and answers with a sealed control " +
    "frame carrying a lease renewal and a posture directive.", { noIndent: true }));
  B.push(figure());
  B.push(caption([
    { t: "Fig. 1.  " },
    { t: "Telemetry flows upward in one second windows; sealed control frames " +
         "return a lease and a posture directive. The gateway acts on its own " +
         "authority when the downward path stops.", i: true },
  ]));
  B.push(body("Every frame header is also the authenticated associated data " +
    "for the AEAD, so node identity, key epoch, sequence number, timestamp and " +
    "posture are authenticated whether or not they are confidential. Posture is " +
    "a four level ladder running from normal through suspicious and anomaly to " +
    "quarantine. Escalation is cheap and reversible. Quarantine isolates a " +
    "single channel while the remaining channels continue to flow, and is " +
    "released explicitly after triage rather than automatically, so that two " +
    "overlapping detections cannot clear one another.", { noIndent: true }));

  // ────────────────── V. Cryptographic construction ──────────────────
  B.push(section("V", "Cryptographic Construction"));
  B.push(subsection("A", "Root establishment and session keys"));
  B.push(body("The server establishes a root key with each gateway using " +
    "ML-KEM-512 [1], authenticated with ML-DSA-44 [2]. Level 1 and level 2 " +
    "parameter sets are chosen deliberately for a constrained deployment; " +
    "Section XIII treats that choice as a limitation rather than a result. " +
    "Sensor nodes do not run post quantum primitives at all. Each performs an " +
    "X25519 exchange [11] bound to a provisioned pre shared key, so a node " +
    "cannot be impersonated without both the long term secret and the ephemeral " +
    "contribution, and the expensive primitives stay on hardware that can " +
    "afford them.", { noIndent: true }));

  B.push(subsection("B", "Authenticated encryption and nonce discipline"));
  B.push(body("Payloads are sealed with AES-256-GCM [8] under a 96 bit " +
    "deterministic nonce formed as the four byte key epoch concatenated with " +
    "the eight byte sequence number. Uniqueness is structural rather than " +
    "probabilistic: the epoch increases on every rotation and the sequence " +
    "counter never repeats within an epoch, so no key and nonce pair can recur " +
    "even across an unclean restart, and no randomness is required at the " +
    "sensor node, which is the component least able to supply it. A guard " +
    "forces rotation before sequence exhaustion, and that guard sits below the " +
    "policy layer so that a learned agent cannot violate the invariant however " +
    "it is trained.", { noIndent: true }));

  // ───────────────────── VI. Security analysis ─────────────────────
  B.push(section("VI", "Security Analysis"));
  B.push(body("Table I maps each adversary capability from Section II-A to " +
    "the mechanism that addresses it and to the evidence we have for that " +
    "mechanism. The right hand column is deliberately explicit about which " +
    "rows rest on a test and which rest on a structural argument, since the " +
    "two carry different weight.", { noIndent: true }));
  B.push(tableHead("I"));
  B.push(tableSub("Adversary capability, mechanism and evidence"));
  B.push(ieeeTable(
    [W(0.30), W(0.38), COL_DXA - W(0.30) - W(0.38)],
    ["Capability", "Mechanism", "Evidence"],
    [
      ["Record now, decrypt later", "ML-KEM-512 root, symmetric per frame",
       "structural"],
      ["Forge or replay telemetry", "AES-256-GCM, header as AAD, replay guard",
       "400 and 33 checks"],
      ["Replay a control frame", "Monotonic control sequence, posture echo",
       "33 checks"],
      ["Silence the control channel", "Lease expiry escalates unaided",
       "24 checks"],
      ["Jam to force lockout", "Expiry never auto quarantines", "24 checks"],
      ["Compromise one node", "Per node PSK and session key, quarantine",
       "114 checks"],
      ["Nonce reuse after restart", "Epoch and sequence nonce, rotation guard",
       "structural, tested"],
    ], false));
  B.push(gap(160));
  B.push(body("Two rows deserve comment. Nonce uniqueness is structural, and " +
    "we tested it only after discovering that the original test could not have " +
    "failed (Section XI-E). And the lease rows are the only ones in the table " +
    "whose mechanism is novel rather than standard practice, which is why " +
    "Section X-D reports them as behavioural scenarios rather than as unit " +
    "tests.", { noIndent: true }));

  // ───────────────── VII. Learned key lifecycle control ─────────────────
  B.push(section("VII", "Learned Key-Lifecycle Control"));
  B.push(subsection("A", "State and actions"));
  B.push(body("The observation has 20 dimensions in five groups: threat " +
    "signals including the calibrated detector score and its fast and slow " +
    "moving averages; control plane state including lease remaining and the " +
    "current directive floor; key lifecycle state including sequence " +
    "consumption, key age and bytes under the current key; local fast path " +
    "evidence the gateway owns rather than receives, including authentication " +
    "failure and replay rejection rates and the count of silent channels; and " +
    "resource state. Nothing in the observation is ground truth about " +
    "compromise.", { noIndent: true }));
  B.push(body("Eight actions are available: hold, rotate the session key, " +
    "refresh the key pool, rotate the root key, escalate posture, de escalate " +
    "posture, quarantine the worst channel, and force an immediate detector " +
    "flush."));

  B.push(subsection("B", "Reward and shield"));
  B.push(body("The reward charges for exposure and for action. Exposure " +
    "accrues per step while an adversary holds a live key. Action costs are " +
    "taken from measurements of the implementation rather than chosen by hand, " +
    "and a false positive is charged separately from a rotation so the agent " +
    "cannot buy safety by alarming. The shield bounds rotation rate, enforces " +
    "minimum posture hold times, refuses de escalation below a server imposed " +
    "floor, and forces rotation before nonce exhaustion.", { noIndent: true }));
  B.push(body("One reward term is deliberately absent and we flag it as a " +
    "design weakness found late: the reward charges for posture transitions but " +
    "not for time spent elevated. Two of three training seeds consequently " +
    "converged on holding the system permanently at the first elevated level. " +
    "The deployed policy is the seed that does not do this, chosen on that " +
    "operational ground rather than on return."));

  B.push(subsection("C", "Training and model selection"));
  B.push(body("The agent is a duelling double deep Q network [5], [6] with " +
    "five step returns, trained for 5000 episodes of 600 steps across three " +
    "seeds, totalling 748,000 gradient steps per seed. Weights are selected by " +
    "periodic greedy evaluation on fixed held out episodes that are disjoint " +
    "from the episodes used for every reported figure, so no confidence " +
    "interval is computed on data that influenced which weights were kept.",
    { noIndent: true }));

  B.push(figure("fig2_training.png", 326, 278));
  B.push(caption([
    { t: "Fig. 2.  " },
    { t: "Training across three seeds, smoothed over 100 episodes. Returns " +
         "improve throughout and compromised steps fall by roughly a third; " +
         "the spread between seeds is the reason model selection uses held out " +
         "episodes rather than the training curve.", i: true },
  ]));

  // ───────────────── VIII. Posture control and alerting ─────────────────
  B.push(section("VIII", "Posture Control and Alerting"));
  B.push(body("The alerting path carries the server's assessment to the " +
    "gateway and carries the gateway's adopted state back. A control frame is " +
    "sealed under a separate control key, carries a monotonic control sequence " +
    "number, and names one of three directive kinds: advise, which the gateway " +
    "may weigh against its own evidence; enforce, which sets a floor the policy " +
    "cannot drop below; and quarantine, which is mandatory, carries a channel " +
    "bitmap, and forces the anomaly posture.", { noIndent: true }));
  B.push(body("Three properties make this fail secure rather than merely " +
    "responsive. First, a lease accompanies every renewal, and its expiry " +
    "escalates the gateway one level and re arms, so a dead control channel " +
    "walks the posture ladder upward over successive periods instead of either " +
    "stalling at normal or slamming to the top on one lost packet. Second, the " +
    "gateway echoes its posture in the next frame header, and a gateway that " +
    "accepts a directive without adopting it is detected within a small number " +
    "of frames. Third, expiry never sets the quarantine bitmap, because " +
    "automatic isolation on a lost control channel would hand the adversary a " +
    "denial of service for the price of jamming."));
  B.push(body("The two learned components meet here rather than directly. The " +
    "detector's calibrated score and the directive derived from it are what the " +
    "policy consumes, so either model can be retrained without touching the " +
    "other, and the interface between them is a documented contract rather than " +
    "an implicit coupling. Section XI-B describes what happened when that " +
    "contract was violated in a way neither component could detect alone."));

  // ───────────────────── IX. Anomaly detection ─────────────────────
  B.push(section("IX", "Anomaly Detection"));
  B.push(body("The detector is a long short term memory autoencoder [12] " +
    "trained on benign windows only. This is not a simplification: a healthy " +
    "installation produces no labelled attacks and never will, so a supervised " +
    "detector cannot be retrained in the field by the people who operate it. " +
    "Raw reconstruction error is converted to a calibrated score by the " +
    "empirical cumulative distribution function of error over held out benign " +
    "data, so a score of 0.99 means worse than 99 percent of benign windows, a " +
    "statement that survives retraining. Per feature error gives channel " +
    "attribution without additional machinery, which the quarantine mechanism " +
    "requires.", { noIndent: true }));
  B.push(body("We train and evaluate on the Mississippi State and Oak Ridge " +
    "National Laboratory power system attack datasets [3], [10], comprising 37 " +
    "scenarios: one no event class, eight natural disturbances and 28 attacks. " +
    "The eight natural disturbances are the reason this dataset was chosen. A " +
    "fault is a large and obvious departure from normal that is not an attack, " +
    "and separating those two is the problem."));

  // ───────────────────────── X. Evaluation ─────────────────────────
  B.push(section("X", "Evaluation"));
  B.push(subsection("A", "Protocol"));
  B.push(body("Policies are compared on identical episodes and differenced per " +
    "seed, because most of the variance between episodes is the episode rather " +
    "than the policy: an episode containing a long intrusion is bad for every " +
    "policy. All reported intervals are 95 percent confidence intervals on that " +
    "paired difference.", { noIndent: true }));

  B.push(subsection("B", "Key lifecycle policy"));
  B.push(tableHead("II"));
  B.push(tableSub("Key lifecycle policies, 15 seeds, 4 episodes of 600 steps"));
  B.push(ieeeTable(
    [W(0.30), W(0.18), W(0.20), W(0.17), COL_DXA - W(0.30) - W(0.18) - W(0.20) - W(0.17)],
    ["Policy", "Return", "Comprom.", "Rotations", "False pos."],
    [
      ["Learned (ours)", "-435.8", "19.3", "12.9", "7.0"],
      ["Oracle reference", "-677.5", "5.3", "5.0", "173.7"],
      ["Threshold", "-1610.9", "75.6", "53.9", "12.8"],
      ["Always-maximum", "-3481.8", "91.8", "60.0", "507.2"],
      ["Never rotate", "-3723.0", "177.4", "0.0", "24.8"],
      ["Fixed interval", "-3946.3", "191.1", "2.0", "24.8"],
    ], true));
  B.push(gap(160));
  B.push(body("The oracle observes the hidden compromise state and is a " +
    "perfect information reference, not an upper bound: it escalates whenever " +
    "an adversary is present and pays heavily in false positives, which is why " +
    "a policy with strictly less information can score above it.",
    { noIndent: true }));
  B.push(body("The learned policy beats the threshold rule by 1175.1 with a 95 " +
    "percent confidence interval of 600.8 to 1749.3, winning on 15 of 15 seeds. " +
    "The figure we consider most meaningful is not the return but the rotation " +
    "count: 74 percent fewer compromised steps using 76 percent fewer key " +
    "rotations. Protection is bought with better timing rather than more work, " +
    "and rotation count is the cost an operator actually pays, since every " +
    "rotation is a post quantum handshake propagated across the fleet."));
  B.push(body("Transfer is complete across the detector grid: the agent wins " +
    "all 27 settings of false positive rate, false negative rate and detection " +
    "delay. It also wins all nine settings of a disturbance regime introduced " +
    "only after the detector had been measured, in which the detector false " +
    "alarms continuously throughout benign grid faults. That regime lies " +
    "outside the training grid entirely and the policy was not retrained for " +
    "it."));

  B.push(figure("fig3_robustness.png", 326, 201));
  B.push(caption([
    { t: "Fig. 3.  " },
    { t: "Robustness across the 27 point detector grid. Every point lies above " +
         "the parity line, so the learned policy wins at every combination of " +
         "false positive rate, false negative rate and detection delay tested. " +
         "The margin widens as the detector degrades, which is the regime a " +
         "deployed detector is most likely to occupy.", i: true },
  ]));

  B.push(subsection("C", "Detector"));
  B.push(tableHead("III"));
  B.push(tableSub("Detector, 55 held out sequences"));
  B.push(ieeeTable(
    [W(0.46), W(0.28), COL_DXA - W(0.46) - W(0.28)],
    ["Measure", "Operational", "vs calm grid"],
    [
      ["Average precision", "0.964", "0.999"],
      ["Recall on attacks", "0.96 to 0.98", ""],
      ["Detection delay (median)", "0.03 s", ""],
      ["Inference per window", "2.5 ms", ""],
      ["False alarms on faults", "0.98 to 1.00", ""],
    ], true));
  B.push(gap(160));
  B.push(body("The operational column counts natural disturbances as " +
    "negatives, which is the question an operator actually asks, since a storm " +
    "that raises an attack alarm is a false alarm whatever the physics were. " +
    "The 0.999 column excludes them and is close to meaningless. Per scenario " +
    "recall has a median of 1.000 across the 28 attack types, and the two " +
    "weakest scenarios are both line maintenance with relays disabled, so the " +
    "attacks hardest to catch are those disguised as routine engineering work. " +
    "The false alarm rate on natural disturbances is a genuine failure and " +
    "Section XII argues what it does and does not permit us to claim.",
    { noIndent: true }));

  B.push(subsection("D", "End to end behaviour"));
  B.push(body("The integrated system passes 24 of 24 behavioural checks across " +
    "four scenarios: normal operation; an injected attack driving escalation " +
    "and rotation with the posture echo verified; loss of the control channel, " +
    "in which the gateway escalates unaided while telemetry continues to flow " +
    "and no channel is quarantined; and quarantine of a single channel followed " +
    "by recovery, triage and release. The 95th percentile cycle time is 41 ms " +
    "against a one second budget on the host implementation.", { noIndent: true }));

  B.push(subsection("E", "Hardware results"));
  B.push(body([
    { t: "The figures in Table IV are " },
    { t: "placeholders", i: true },
    { t: ". Bring-up of the ESP32 sensor node and the gateway single board " +
         "computer is scheduled and the firmware is complete and host tested, " +
         "but the measurements have not been taken. The values are consistent " +
         "with the platforms and with the host measurements, and they are " +
         "included so that the structure of the finished evaluation is visible. " +
         "Every one must be replaced before this table is cited anywhere." },
  ], { noIndent: true }));
  B.push(tableHead("IV"));
  B.push(tableSub("Hardware figures (PLACEHOLDER, pending bring-up)"));
  B.push(ieeeTable(
    [W(0.52), W(0.24), COL_DXA - W(0.52) - W(0.24)],
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
    ], false));
  B.push(gap(160));
  B.push(body("The one measured row is informative on its own. Sealing a frame " +
    "costs 0.019 ms on the host against 7.03 ms of serial transmission, so the " +
    "link and not the cryptography sets the achievable sampling rate. We expect " +
    "that ratio to narrow but not to invert on the target, which would " +
    "contradict the common assumption that cryptography is the bottleneck on " +
    "constrained hardware. Confirming or refuting that is the first measurement " +
    "to take at bring-up.", { noIndent: true }));

  B.push(subsection("F", "Statistical testing and verification"));
  B.push(body("Both custom primitives pass NIST SP 800-22 [4] at 55 sequences " +
    "of 100,000 bits. The key derivation extractor passes every control " +
    "validated test and the chaotic keystream passes with a pooled proportion " +
    "of 162 of 165 across three corpora under different keys. Section XI-C " +
    "describes the control procedure without which these results would have " +
    "been reported with the opposite sign. Automated verification totals 763 " +
    "checks across the C and Python implementations, including 400 against NIST " +
    "AES vectors, 114 on the sensor node, 17 cross language key derivation " +
    "vectors, and 24 integrated scenarios.", { noIndent: true }));

  // ───────────────────── XI. Negative results ─────────────────────
  B.push(section("XI", "Negative Results"));
  B.push(body("Each of the following produced a plausible result that was " +
    "wrong. Three of the five generalise well beyond this system.",
    { noIndent: true }));

  B.push(subsection("A", "A chaos only keystream failed outright"));
  B.push(body("The first masking design produced its keystream from coupled " +
    "logistic maps alone. Across the full parameter space, 100 percent of draws " +
    "fell below 7.99 bits per byte. At a coupling strength of 0.4 the stream " +
    "measured 3.26 bits per byte, with a single byte value occupying 36 percent " +
    "of the output. The cause is synchronisation: coupling drives the maps " +
    "toward a common trajectory, and combining the same bit slice of two " +
    "synchronised states collapses it. Folded extraction, a Lyapunov based " +
    "filter and fixed point arithmetic each left between 20 and 60 percent of " +
    "the parameter space failing. The deployed hybrid measures 7.99995 bits per " +
    "byte at every posture. A single favourable parameter choice would have " +
    "passed, which is our reason for reporting the sweep.", { noIndent: true }));

  B.push(subsection("B", "A calibration contract that contradicted its surrogate"));
  B.push(body([
    { t: "The agent trained against a surrogate whose benign scores were drawn " +
         "from a Beta(1.5, 6) distribution with mean 0.20, describing a " +
         "detector that reads near zero when nothing is wrong. But empirical " +
         "distribution calibration makes benign scores " },
    { t: "uniform", i: true },
    { t: " on the unit interval by construction, and the trained detector " +
         "measured mean 0.503, Beta(0.96, 0.95). Both components were written " +
         "to the same specification, by the same authors, and contradicted each " +
         "other." },
  ], { noIndent: true }));
  B.push(body("The consequence appeared only when both trained components were " +
    "connected. On calm traffic the policy's hold action collapsed from 60.1 " +
    "percent of steps in simulation to 5 percent in the live system, and " +
    "rotation rose from 7.0 percent to 42 percent. Re fitting the surrogate to " +
    "the measured distribution and retraining restored the behaviour and " +
    "improved every metric in Table II. The error also concealed a harder " +
    "property: under a uniform benign distribution roughly 10 percent of " +
    "entirely normal windows score above 0.9, so a single high score is not " +
    "evidence of anything, and every alarm threshold in the control plane had " +
    "to be re derived. Domain randomisation over the detector's error rates " +
    "could not protect against an error in the parameterisation itself."));

  B.push(figure("fig4_scores.png", 326, 187));
  B.push(caption([
    { t: "Fig. 4.  " },
    { t: "Measured score distributions against the distribution the agent was " +
         "trained to expect. Calibration forces benign scores to be uniform, " +
         "while the surrogate assumed mass near zero. Attacks and natural " +
         "disturbances both concentrate near 1.0, which is why the detector " +
         "cannot separate them.", i: true },
  ]));

  B.push(subsection("C", "Statistical testing needs a control corpus"));
  B.push(body("Running SP 800-22 against a cryptographically secure generator " +
    "alongside the primitives under test, six of twelve tests failed on that " +
    "known good input at 100,000 bit sequences, several requiring roughly one " +
    "million bits to be meaningful. Without that control the headline would " +
    "have been that the key derivation function fails half the battery. " +
    "Excluding the tests the control cannot pass, the extractor matches the " +
    "control test for test across the whole battery, passing and failing the " +
    "same ones, which is what establishes the exclusions as artefacts of the " +
    "tool. One marginal failure in the masking layer did not reproduce across " +
    "two further corpora.", { noIndent: true }));

  B.push(subsection("D", "A selection rule on too little data is a randomiser"));
  B.push(body("Training kept the best weights by evaluation on three held out " +
    "episodes. One of the three scored almost identically for every candidate " +
    "and carried no information, so the ranking rested on essentially one " +
    "episode, and re ranking on 15 episodes reversed the winner. Selection on " +
    "three episodes was measurably worse than no selection at all: the final " +
    "weights of each run outscored the weights that rule had chosen. A " +
    "selection rule evaluated on too little data is not a conservative version " +
    "of a good one.", { noIndent: true }));

  B.push(subsection("E", "A safety gate that could not fire"));
  B.push(body("The acceptance criterion for nonce safety was zero exhaustion " +
    "events, and the evaluation reported zero forced rotations. It was not " +
    "evidence. At the episode length used, the guard rail could not be reached " +
    "even by a policy that never rotated, so a do nothing agent would have " +
    "scored identically. Re run at an episode length where the threshold is " +
    "reachable, the result holds and peak sequence consumption sits two orders " +
    "of magnitude below the limit. A safety property that cannot fail within " +
    "the window you measured has not been measured.", { noIndent: true }));

  // ───────────────────────── XII. Discussion ─────────────────────────
  B.push(section("XII", "Discussion"));
  B.push(body("The detector's behaviour on natural disturbances constrains how " +
    "this system may be described. Reconstruction error measures the unusual, " +
    "and a fault is extremely unusual, so the mechanism that catches attacks is " +
    "the one that fires on weather. We therefore describe the component as a " +
    "disturbance detector rather than an attack detector, and locate the " +
    "discrimination in the policy that consumes its output.", { noIndent: true }));
  B.push(body("This is not a rescue of a failed component. The architecture was " +
    "built for a detector that is often wrong: the score is calibrated input to " +
    "a policy rather than a verdict, the policy is trained with an explicit " +
    "false positive cost, and the response to suspicion is to isolate and " +
    "continue rather than to stop. A detector with a known false alarm rate on " +
    "faults is usable in this architecture. One with an unmeasured rate is not, " +
    "which is the practical reason to run the experiment even when the answer " +
    "is unwelcome."));
  B.push(body("The negative results share a structure worth naming. In each " +
    "case the component was correct in isolation and the error lived in the " +
    "interface: between a calibration convention and a training assumption, " +
    "between a test and the length of the window it ran in, between a selection " +
    "rule and the amount of data it was given. Unit tests cannot find errors of " +
    "this kind, because every unit behaves as specified."));

  // ───────────────────────── XIII. Limitations ─────────────────────────
  B.push(section("XIII", "Limitations"));
  B.push(body("The hardware figures in Table IV are placeholders and the paper " +
    "must not be submitted until they are measured. The detector deployed in " +
    "the integrated system is trained on synthetic benign traffic, because the " +
    "public dataset's 128 synchrophasor features do not transfer to a five " +
    "channel installation; the public data earns the detection numbers and the " +
    "integration demonstrates the control path, and neither substitutes for the " +
    "other.", { noIndent: true }));
  B.push(body("Channel attribution accuracy is unmeasurable on the public data, " +
    "whose labels name scenarios rather than manipulated instruments. SP 800-22 " +
    "is a necessary and not a sufficient condition; a counter encrypted under " +
    "AES passes it. The shield's forced rotation path is never exercised by the " +
    "trained agent, so it rests on unit tests. The level 1 and level 2 post " +
    "quantum parameter sets are a deployment time decision to revisit. And the " +
    "key derivation pre mix adds no provable strength, as Section III-A states."));

  // ───────────────────────── XIV. Future work ─────────────────────────
  B.push(section("XIV", "Future Work"));
  B.push(body("Four items follow from the limitations. Collecting benign " +
    "telemetry from the instrumented rig and retraining the detector on it is " +
    "the step that converts the method into a deployable component, and it " +
    "requires no labelled attacks. Adding a standing cost for time spent above " +
    "normal posture should remove the degenerate behaviour described in " +
    "Section VII-B. Modelling the detector's two false positive rates, roughly " +
    "0.05 on a calm grid and close to 1.0 during a fault, would let the agent " +
    "condition on whether the grid is disturbed. And signing the gateway's " +
    "encapsulation key with its existing signature key, then rotating that " +
    "keypair per epoch, closes an implicit trust assumption and adds forward " +
    "secrecy to the root transfer.", { noIndent: true }));

  // ───────────────────────── XV. Conclusion ─────────────────────────
  B.push(section("XV", "Conclusion"));
  B.push(body("A learned key lifecycle policy, trained against a distribution " +
    "of detector qualities rather than a fixed detector, protects a post " +
    "quantum industrial telemetry path with 76 percent fewer key rotations than " +
    "a threshold rule while leaving 74 percent less time under adversary " +
    "control, and transfers to detector behaviour it never saw in training. The " +
    "supporting constructions are a fail safe hybrid key derivation whose output " +
    "is never weaker than its own fallback, a posture adaptive masking layer " +
    "applied outside the authenticated encryption, and a lease based alerting " +
    "plane in which silence is evidence.", { noIndent: true }));
  B.push(body("The engineering result we would emphasise is subtler. Two " +
    "components built to one specification can disagree about what a number " +
    "means, and no amount of testing within either component reveals it. We " +
    "recommend an explicit interface measurement step whenever a learned " +
    "controller consumes a learned signal, a control corpus alongside any " +
    "statistical randomness result, and a check that each safety criterion " +
    "could have failed within the window it was measured in."));

  B.push(section(null, "Acknowledgment"));
  B.push(body("The authors thank the maintainers of the Mississippi State " +
    "University and Oak Ridge National Laboratory power system attack datasets, " +
    "recovered for this work from the Internet Archive after the original host " +
    "became unavailable.", { noIndent: true }));

  return B;
};
