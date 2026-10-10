// References for the system paper.
//
// Entries 9 to 36 are carried over from the Semester 4 project report, with
// one change: page ranges that were clearly placeholders in that document have
// been removed rather than reproduced. In the source, "pp. 5-43" appeared on
// four unrelated papers, "pp. 11-32" on three, "pp. 5-32" on two, and one
// entry read "pp. 18-18". Three entries also gave the venue only as
// "in Proc. IEEE Conf." with no conference named.
//
// VERIFY BEFORE SUBMISSION: entries 20, 28, 29 and 33 need their real venue
// and page numbers. Reviewers check these, and a fabricated page range is
// worse than an incomplete one.
//
// No en dashes in page ranges.
module.exports = [
  // Standards and primitives
  'National Institute of Standards and Technology, "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS 203, Aug. 2024.',
  'National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard," FIPS 204, Aug. 2024.',
  'M. Dworkin, "Recommendation for block cipher modes of operation: Galois/Counter Mode (GCM) and GMAC," NIST SP 800-38D, Nov. 2007.',
  'J. Kelsey, S. Chang and R. Perlner, "SHA-3 derived functions: cSHAKE, KMAC, TupleHash and ParallelHash," NIST SP 800-185, Dec. 2016.',
  'H. Krawczyk and P. Eronen, "HMAC-based extract-and-expand key derivation function (HKDF)," RFC 5869, May 2010.',
  'D. J. Bernstein, "Curve25519: New Diffie-Hellman speed records," in Proc. Public Key Cryptography, 2006, pp. 207-228.',
  'A. Rukhin et al., "A statistical test suite for random and pseudorandom number generators for cryptographic applications," NIST SP 800-22 Rev. 1a, Apr. 2010.',
  'International Electrotechnical Commission, "Power systems management and associated information exchange: Data and communications security," IEC 62351, 2020.',

  // The quantum threat
  'V. Bhatia and K. Ramkumar, "An efficient quantum computing technique for cracking RSA using Shor algorithm," in Proc. IEEE 5th Int. Conf. Computing, Communication and Automation (ICCCA), 2020.',
  'J. P. Dumas, K. Soni and A. Rasool, "Evolution of quantum computing based on Grover search algorithm," 2019.',
  'Google Research, "The quantum echoes algorithm breakthrough," Oct. 2025. [Online]. Available: https://blog.google/technology/research/quantum-echoes-willow-verifiable-quantum-advantage/',

  // Post-quantum cryptography on constrained hardware
  'A. Khalid, S. McCarthy, M. O Neill and W. Liu, "Lattice-based cryptography for IoT in a quantum world: Are we ready?," in Proc. IEEE Conf. Cryptography and IoT Security, 2019.',
  'M. A. G. de la Torre, I. A. Morales-Sandoval and L. H. Encinas, "Post-quantum wireless-based key encapsulation mechanism via CRYSTALS-Kyber for resource-constrained devices," IEEE Access, vol. 13, 2025.',
  'W. B. Dias, A. Maiga and Z. Y. Shae, "Kyber-KEM-Ascon: Benchmarking a lightweight post-quantum KEM on IoT devices," Preprint, 2025.',
  'D.-T. Dam, T.-H. Nguyen, T.-H. Tran, B. Kieu-Do-Nguyen and T.-T. Nguyen, "An efficient method for accelerating Kyber and Dilithium post-quantum cryptography," 2024.',
  'Y. Yang, Y. Lin, J. Xiao and Z. Zhong, "Feasibility discussion of quantum cryptography for Internet of Things security: a literature review," Optical and Quantum Electronics, vol. 57, art. 264, 2025.',
  'I. Radhakrishnan, S. Jadon and P. B. Honnavalli, "Efficiency and security evaluation of lightweight cryptographic algorithms for resource-constrained IoT devices," Sensors, vol. 24, no. 12, art. 4008, 2024.',
  'H. Almomani et al., "Securing Internet of Vehicles communications: A biometric and hash-key derivation function based approach," in Proc. 25th Int. Arab Conf. Information Technology (ACIT), 2024.',

  // Chaotic constructions
  'H. Wen, Y. Lin, S. Kang, X. Zhang and K. Zou, "Secure image encryption algorithm using chaos-based block permutation and weighted bit planes chain diffusion," iScience, vol. 27, no. 1, art. 108610, Jan. 2024.',
  'M. Ghebleh, A. Kanso and H. Noura, "An image encryption scheme based on irregularly decimated chaotic maps," Signal Processing: Image Communication, vol. 29, no. 5, 2014.',
  'D. Yang, Z. Liu and J. Zhou, "Chaos optimization algorithms based on chaotic maps with different probability distribution and search speed for global optimization," Communications in Nonlinear Science and Numerical Simulation, vol. 19, no. 4, 2014.',
  'A. Kotangale and M. S. Kumar, "An iterative quantum chaotic security method design for big data deployments using a multi-model framework for key generation, threat modelling, and anomaly-resilient validation," MethodsX, vol. 15, art. 103643, Dec. 2025.',

  // Industrial control systems and detection
  'R. M. Lee, M. J. Assante and T. Conway, "Analysis of the cyber attack on the Ukrainian power grid," E-ISAC and SANS ICS, Mar. 2016.',
  'Y. Yang, K. McLaughlin, S. Sezer, T. Littler, E. G. Im, B. Pranggono and H. F. Wang, "Multiattribute SCADA-specific intrusion detection system for power networks," IEEE Trans. Power Delivery, vol. 29, no. 3, 2014.',
  'S. Pan, T. Morris and U. Adhikari, "Developing a hybrid intrusion detection system using data mining for power systems," IEEE Trans. Smart Grid, vol. 6, no. 6, pp. 3104-3113, 2015.',
  'U. Adhikari, S. Pan, T. Morris, R. Borges and J. Beaver, "Industrial control system (ICS) cyber attack datasets," Mississippi State University and Oak Ridge National Laboratory, 2014.',
  'P. Malhotra, L. Vig, G. Shroff and P. Agarwal, "Long short term memory networks for anomaly detection in time series," in Proc. European Symp. Artificial Neural Networks, 2015, pp. 89-94.',
  'Q. Vo, "Anomaly detection in IoT sensor energy consumption using LSTM neural networks and Isolation Forest," 2024.',
  'J. Li, X. Zhang, H. Xiang et al., "Federated anomaly detection with isolation forest for IoT network traffics," in Proc. IEEE 29th Int. Conf. Parallel and Distributed Systems (ICPADS), 2023.',

  // Learning for control and security
  'H. van Hasselt, A. Guez and D. Silver, "Deep reinforcement learning with double Q-learning," in Proc. AAAI Conf. Artificial Intelligence, 2016, pp. 2094-2100.',
  'Z. Wang, T. Schaul, M. Hessel, H. van Hasselt, M. Lanctot and N. de Freitas, "Duelling network architectures for deep reinforcement learning," in Proc. Int. Conf. Machine Learning, 2016, pp. 1995-2003.',
  'X. Fang, L. Zheng, X. Fang, W. Chen, K. Fang, L. Yin and H. Zhu, "Pioneering advanced security solutions for reinforcement learning-based adaptive key rotation in Zigbee networks," Scientific Reports, vol. 14, art. 13931, 2024.',
  'S. Bhimshetty and A. Victor, "Energy-efficient deep Q-network for reinforcement learning in wireless IoT routing protocols," 2024.',
  'J. Tobin, R. Fong, A. Ray, J. Schneider, W. Zaremba and P. Abbeel, "Domain randomization for transferring deep neural networks from simulation to the real world," in Proc. IEEE/RSJ Int. Conf. Intelligent Robots and Systems, 2017, pp. 23-30.',

  // Adjacent grid security
  'M. Alshowkan, P. G. Evans, M. Starke, D. Earl and N. A. Peters, "Authentication of smart grid communications using quantum key distribution," Scientific Reports, vol. 12, art. 12731, 2022.',
  'G. Falco, A. Viswanathan, C. Caldera and H. Shrobe, "A master attack methodology for an AI-based automated attack planner for smart cities," IEEE Access, vol. 6, pp. 48360-48373, 2018.',
];
