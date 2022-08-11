# IndexOramCoDesign

This is the repository associated with the corresponding master thesis by Philipp Imperatori.
Further explanations how tu use this repo can be found in the folders *frontend* and *backend*.
The first contains a simulator to run YCSB-like workloads with our design. The latter contains the actual design.

Abstract:
In the age of cloud computing and digitization, encrypting data is an obvious choice in most contexts.
Using proper protocols is the approved solution to ensure confidentiality against the growing number of cyberattacks.
However, research in recent years has shown that the access patterns to encrypted data alone can reveal significant information about the data itself.
This severely impacts the security of databases that are encrypted for confidentiality, as several practical attacks have demonstrated.
Therefore, various works developed new schemes ensuring obliviousness to mitigate the risks.
Obliviousness prevents access pattern leakage and is often achieved using an Oblivious RAM (ORAM), a so-called "cryptographic primitive".
This is accompanied by high overhead, as accesses must be hidden by randomly accessing more data than necessary.
To the best of our knowledge, none of the prior works have accomplished a good oblivious design to make the use case of a relational database primarily queried by transactional workloads supporting range queries feasible.
In particular, we identified the great potential for optimizing the query performance of an oblivious sorted index, which is common in a transactional relational database.
Therefore, we adopted the concept of oblivious data structures from prior studies to build an oblivious B-Tree as a baseline.
This thesis contributes with its Index-ORAM-Co-Design, which focuses on the integrated approach of logical indexing and physical storage.
Its architecture is based on a secure enclave at the untrusted server.
It orchestrates the client query workloads against the encrypted database in ORAM.
We present five optimizations that are the building blocks of this generalizable concept.
This includes a novel approach that leverages overlapping prefixes inside ORAM to prevent deduplication of the physical memory.
Moreover, we present a flexible Packet Path ORAM, which adopts the well-known Path ORAM for dynamic data.
We complete the Path ORAM optimization by Lazy Reshuffling, which reduces data moving costs.
In addition, we provide a concept of managing queries in an oblivious fashion that allows deduplicating logical index accesses.
Lastly, we propose the Index Locality Cache, which extracts valuable data of the ORAM overhead to minimize following ORAM accesses.
As a result of these optimizations, we achieved an excellent gain of up to 69\% less workload time and up to 92\% fewer expensive ORAM accesses compared to the baseline.
In addition to the novel Index-ORAM-Co-Design, this thesis contributes with a comprehensive implementation in Rust, a programming language known for its security benefits.
The implementation leverages the widely available Intel SGX to enable a trusted orchestrator on the database server.
It facilitates future studies with its simulator front-end and provides a well-designed entrance for further engineering.
