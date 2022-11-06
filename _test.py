from blake3 import blake3

from pure_python_blake3 import *

message = b"We present BLAKE3, an evolution of the BLAKE2 cryptographic hash that is both faster\
and also more consistently fast across different platforms and input sizes. BLAKE3\
supports an unbounded degree of parallelism, using a tree structure that scales up\
to any number of SIMD lanes and CPU cores. On Intel Cascade Lake-SP, peak\
single-threaded throughput is 4x that of BLAKE2b, 8x that of SHA-512, and 12x\
that of SHA-256, and it can scale further using multiple threads. BLAKE3 is also\
efficient on smaller architectures: throughput on a 32-bit ARM1176 core is 1.3x that\
of SHA-256 and 3x that of BLAKE2b and SHA-512. Unlike BLAKE2 and SHA-2, with\
different variants better suited for different platforms, BLAKE3 is a single algorithm\
with no variants. It provides a simplified API supporting all the use cases of BLAKE2,\
including keying and extendable output. The tree structure also supports new use\
cases, such as verified streaming and incremental updates. Since its announcement in 2012, BLAKE2 [5]\
has seen widespread adoption, in large part because of its superior performance in software.\
BLAKE2b and BLAKE2s are included in OpenSSL and in the Python and Go standard libraries.\
BLAKE2b is also included as the b2sum utility in GNU Coreutils, as the generichash API in \
Libsodium, and as the underlying hash function for Argon2 [9], the winner of the Password \
Hashing Competition in 2015. A drawback of BLAKE2 has been its large number of incompatible variants.\
The performance tradeoffs between different variants are subtle, and library support is uneven.\
BLAKE2b is the most widely supported, but it is not the fastest on most platforms. BLAKE2bp\
and BLAKE2sp are more than twice as fast on modern x86 processors, but they are sparsely\
supported and rarely adopted. BLAKE3 eliminates this drawback. It is a single algorithm with no variants, designed for\
consistent high performance in software on all platforms. The biggest changes from BLAKE2\
to BLAKE3 are: 015.A drawback of BLAKE2 has been its large number of incompatible variants.\
ending message 12345678.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"

print(len(message))

message_1024 = message[:1024]
message_2048 = message[1024:2048]
message_3072 = message[2048:3072]
message_4096 = message[3072:4096]

# python_hasher = Hasher()
# python_hasher.update(message_1024)
# print(f"Actual Output H_1: {python_hasher.finalize().hex()}")
# print(f"Hasher 1024 CV Stack: {python_hasher.cv_stack}")
# python_hasher.update(message_2048)
# print(f"Actual Output H_1_2: {python_hasher.finalize().hex()}")
# print(f"Hasher 2048 CV Stack: {python_hasher.cv_stack}")
# print(f"Hasher 2048 CV: {parent_cv(python_hasher.cv_stack[0], python_hasher.chunk_state.output().chaining_value(), IV, PARENT)}")
# python_hasher.update(message_3072)
# print(f"Hasher 3072 CV Stack: {python_hasher.cv_stack}")
# python_hasher.update(message_4096)
# print(f"Hasher 4096 CV Stack: {python_hasher.cv_stack}")

prover1_2 = Hasher()

prover3 = Hasher()
prover3.chunk_state = ChunkState(IV, 2, 0)

prover4 = Hasher()
prover4.chunk_state = ChunkState(IV, 3, 0)

prover3.update(message_3072)
prover4.update(message_4096)

print(prover1_2.chunk_state.chunk_counter)
prover1_2.update(message_1024)

prover1_2.update(message_2048)

#print(f"Prover Output H_1: {prover.chunk_state.output().root_output_bytes(length=32).hex()}")
print(f"Prover1_2 Output CV: {parent_cv(prover1_2.cv_stack[0], prover1_2.chunk_state.output().chaining_value(), IV, PARENT)}")
print(f"Prover1_2 Input CV: {prover1_2.chunk_state.output().input_chaining_value}")

print(f"Prover 3 Output CV: {prover3.chunk_state.output().chaining_value()}")
print(f"Prover 4 Output CV: {prover4.chunk_state.output().chaining_value()}")

hash1 = Hasher()
hash2 = Hasher()
hash2.chunk_state = ChunkState(IV, 1, 0)

hash1.update(message_1024)
hash2.update(message_2048)

hash1_2_cv = parent_cv(hash1.chunk_state.output().chaining_value(), hash2.chunk_state.output().chaining_value(), IV, PARENT)
print(f"hash1_2_cv: {hash1_2_cv}")
hash3_4_cv = parent_cv(prover3.chunk_state.output().chaining_value(), prover4.chunk_state.output().chaining_value(), IV, PARENT)
print(f"hash3_4_cv: {hash3_4_cv}")

prover3_4 = Hasher()
prover3_4.chunk_state = ChunkState(IV, 2, 0)
prover3_4.update(message_3072)
prover3_4.update(message_4096)

print(f"Prover3_4 Output CV: {parent_cv(prover3_4.cv_stack[0], prover3_4.chunk_state.output().chaining_value(), IV, PARENT)}")

proverRoot = prover1_2
proverRoot.update(message_3072)
proverRoot.update(message_4096)

# hash3_4_cv = parent_cv(prover3.cv_stack[0], prover3.chunk_state.output().chaining_value(), IV, PARENT)

print(f"Prover Output CV: {parent_cv(hash1_2_cv, hash3_4_cv, IV, PARENT)}")
tempCV = parent_cv(proverRoot.cv_stack[1], proverRoot.chunk_state.output().chaining_value(), IV, PARENT)
tempCV = parent_cv(proverRoot.cv_stack[0], tempCV, IV, PARENT)
#print(f"Actual Output CV: {parent_cv(proverRoot.cv_stack[0], proverRoot.chunk_state.output().chaining_value(), IV, PARENT)}")
print(f"Actual Output CV: {tempCV}")

print(bytes([tempCV[0]]))

print(f"Prover Output: {parent_output(hash1_2_cv, hash3_4_cv, IV, ROOT).root_output_bytes(length=32).hex()}")
print(f"Actual Output: {proverRoot.finalize().hex()}")


