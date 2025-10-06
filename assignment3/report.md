CSC-321 Module 3 Assignment – Public Key Cryptography
Students: Emanuel Gonzalez, Sabrina Huang
Summary
This project implemented and analyzed core public-key cryptography algorithms: Diffie-Hellman key exchange and RSA encryption. We tested secure key generation, AES-CBC message exchange, and demonstrated several man-in-the-middle (MITM) and malleability attacks that show why authentication and padding are essential in practice.
Task 1 – Diffie-Hellman Key Exchange
We implemented the classical DH protocol using both small toy parameters (q = 37, α = 5) and a 1024-bit IETF prime. Each party generated a private key x, computed its public value α^x mod q, exchanged values, and derived a shared secret s = Y^x mod q, then hashed it with SHA-256 to form a 128-bit AES key.
Results
With small numbers, both parties derived the same shared secret (1) and successfully decrypted “Hi Bob!”.
Using 1024-bit parameters, the protocol remained efficient and secure.
Observation
Small parameters are trivially breakable by brute-force; large primes make discrete-log attacks infeasible.
Task 2 – MITM Attacks on Diffie-Hellman
(a) Replacing YA and YB with q
Mallory intercepted and replaced both public keys with q.
Since q^x mod q = 0, Alice and Bob computed 0 as their shared secret, allowing Mallory to derive the same AES key and decrypt messages.
Attack succeeded.
(b) Tampering with Generator α
We tested α = 1, α = q, and α = q-1.
Each made the shared secret predictable (1 or 0), allowing Mallory to decrypt communications.
All attacks succeeded.
Why They Work
The DH protocol lacks authentication—anyone can substitute values without detection.
Modern protocols (e.g., TLS 1.3, Signal) solve this by signing or authenticating public values.
Task 3 – RSA Implementation and Malleability
(a) Textbook RSA
We generated 512-bit keys using e = 65537.
Messages encrypt as c = m^e mod n and decrypt as m = c^d mod n.
Encryption and decryption of “Hello!” worked correctly.
RSA verified mathematically.
(b) RSA Malleability Attack
Using RSA’s multiplicative property, Mallory modified ciphertext c' = 2^e mod n, forcing Alice to decrypt to 2.
Both derived the same AES key SHA256(2), allowing Mallory to read the message.
Attack successful.
(c) Signature Malleability
Given signatures sig1 = m1^d and sig2 = m2^d, Mallory forged sig3 = sig1 × sig2 mod n, a valid signature for m3 = m1 × m2 mod n.
Forgery verified as valid.
Fix
Use OAEP padding for encryption and PSS for signatures to prevent determinism and malleability.
Key Takeaways
Small parameters = insecure. Discrete-log and factorization attacks become trivial.
Authentication is essential. Unauthenticated key exchange is vulnerable to MITM.
Padding and randomness eliminate malleability and replay attacks.
Modern standards (TLS 1.3, RSA-OAEP, ECDHE) implement these safeguards.
References
Yocam, E. (2025). CSC 321 Module 3 Lectures & Terminology. Cal Poly SLO.
Diffie & Hellman (1976). New Directions in Cryptography. IEEE IT.
Rivest et al. (1978). Communications of the ACM.
Katz & Lindell (2014). Introduction to Modern Cryptography.