from pure_python_blake3 import *

class Verifier:
    def __init__(self, data):
        self.root_hash = Hasher(data).finalize().hex()

    def verify(self, proofs):
        chunk_chain = proofs[0] # Initialize with the 1st proof (Hash of Data)
        for cv in proofs[1:-1]:
            chunk_chain = parent_cv(chunk_chain, cv, IV, PARENT)
        prover_root_hash = parent_output(chunk_chain, proofs[-1], IV, ROOT)
        return prover_root_hash == self.root_hash