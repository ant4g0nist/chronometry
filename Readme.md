# Chronometry
[Chronometry](chronometry.io) is a tamper-proof platform for hackers and bug bounty hunters to record & keep track of Proof-of-Hacks (PoH). The word Chronometry refers to the science of accurate time measurement.

"Proof of Hack" refer to the evidence or demonstration that a hacker has successfully exploited a vulnerability in a system or application. This proof is used to verify the authenticity of the vulnerability report.

Hackers usually tweet hashes as a means of sharing the details of a specific exploit or vulnerability with other members of the hacking community. The hash is a unique representation of a Proof-of-Concept file or a vulnerability report submitted to platforms like HackerOne/WeFuzz, and can be used to confirm the authenticity of the data or to check if it has been tampered with. 

By generating a hash of the report before it is submitted and recording it on [Chronometry](chronometry.io), a Hacker can create a unique and verifiable fingerprint of the report that can be used to confirm its authenticity at a later time. This can be useful for resolving disputes or for providing proof of discovery in cases where multiple parties claim to have reported the same vulnerability.

The most common forms of proof-of-hack include:

- A detailed description of the vulnerability and how it can be exploited
- A proof-of-concept (PoC) exploit code
- A video or screenshot demonstrating the successful exploitation of the vulnerability
- A detailed explanation of the impact of the vulnerability
- A description of the steps taken to mitigate the vulnerability

Chronometry uses [Trillian](https://github.com/google/trillian)

Trillian implements a Merkle tree whose contents are served from a data storage layer, to allow scalability to extremely large trees. On top of this Merkle tree, Trillian provides the following:

An append-only Log mode, analogous to the original Certificate Transparency logs. In this mode, the Merkle tree is effectively filled up from the left, giving a dense Merkle tree.

---
- Author: [ant4g0nist](https://twitter.com/ant4g0nist)
