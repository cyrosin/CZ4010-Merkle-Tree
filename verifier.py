from pure_python_blake3 import *

class Verifier:
    def __init__(self, data):
        hasher = Hasher()
        hasher.update(data)
        self.root_hash = hasher.finalize().hex()

    def verify(self, proof):
        print("proof", [x.data for x in proof])
        if len(proof) == 1:
            return self.root_hash == proof[0].data
        elif len(proof) == 2:
            leftChild, rightChild = (proof[0].data, proof[1].data) if proof[0].left else (proof[1].data, proof[0].data)
            proof_root_hash = parent_output(leftChild, rightChild, IV, ROOT)
        else:
            leftChild, rightChild = (proof[0].data, proof[1].data) if proof[0].left else (proof[1].data, proof[0].data)
            print(f"left Child {leftChild}")
            print(f"right Child {rightChild}")
            chain = parent_cv(leftChild, rightChild, IV, PARENT)

            print(f'initial chain: {chain}')

            for proofNode in proof[2:-1]:
                chain = parent_cv(proofNode.data, chain, IV, PARENT) if proofNode.left else parent_cv(chain, proofNode.data, IV, PARENT)
                print(f'chain: {chain}')

            proof_root_hash = parent_output(proof[-1].data, chain, IV, ROOT) if proof[-1].left else parent_output(chain, proof[-1].data, IV, ROOT)
        
        print(self.root_hash)
        print(proof_root_hash.root_output_bytes(length=32).hex())

        return self.root_hash == proof_root_hash.root_output_bytes(length=32).hex()

        # chunk_chain = proof[0] # Initialize with the 1st proof (Hash of Data)
        # for cv in proofs[1:-1]:
        #     chunk_chain = parent_cv(chunk_chain, cv, IV, PARENT)
        # prover_root_hash = parent_output(chunk_chain, proofs[-1], IV, ROOT)
        # return prover_root_hash == self.root_hash