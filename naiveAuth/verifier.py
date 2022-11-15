
from pure_python_blake3 import *
from naiveAuth.proofNode import ProofNode
from blake3 import blake3
import secrets
import sys

class Verifier:
    def __init__(self, data, isPath=False):
        hasher = blake3() # Using the blake3 (PyO3) package speeds up the hashing

        if isPath:
            # If provided with a list of filepaths, preprocess them by hashing them
            if isinstance(data, (list, tuple)):
                data = self._hashfiles(data)
                hasher.update(data)
            else:
                with open(data, 'rb') as f:
                    hasher.update(f.read())

        else:
            if (type(data) != bytes):
                data = bytes(data)
            hasher.update(data)

        self.root_hash = hasher.digest().hex()

    def issueChallenge(self):
        return secrets.randbelow(sys.maxsize)

    def verify(self, proofBytes):
        proof = self.bytesToProofNodes(proofBytes)

        if len(proof) == 1:
            return self.root_hash == proof[0].data
        elif len(proof) == 2:
            leftChild, rightChild = (proof[0].data, proof[1].data) if proof[0].left else (proof[1].data, proof[0].data)
            proof_root_hash = parent_output(leftChild, rightChild, IV, ROOT)
        else:
            leftChild, rightChild = (proof[0].data, proof[1].data) if proof[0].left else (proof[1].data, proof[0].data)
            chain = parent_cv(leftChild, rightChild, IV, PARENT)

            for proofNode in proof[2:-1]:
                chain = parent_cv(proofNode.data, chain, IV, PARENT) if proofNode.left else parent_cv(chain, proofNode.data, IV, PARENT)

            proof_root_hash = parent_output(proof[-1].data, chain, IV, ROOT) if proof[-1].left else parent_output(chain, proof[-1].data, IV, ROOT)

        return self.root_hash == proof_root_hash.root_output_bytes(length=32).hex()

    def _hashfiles(self, filepath_list):
        """
        Given a list of filepaths, hash them using blake3 to obtain 1024 byte hash representations 
        of their data, then construct the merkle tree for authentication using these representations
        """
        byteArray = bytearray(b'')

        for filepath in filepath_list:

            with open(filepath, 'rb') as f:
                fileBytes = f.read()
                hashed_file = blake3(fileBytes).digest(length = 1024)
                byteArray.extend(hashed_file)
        
        return byteArray

    def bytesToProofNodes(self, proofBytes):
        proof = []
        
        proofBytesArray = bytearray(proofBytes)

        if len(proofBytesArray) <= 33:
            proofNodeData = proofBytesArray[:32].hex()
            isLeftIdx = None
            proofNode = ProofNode(proofNodeData, isLeftIdx)
            proof.append(proofNode)
        else:
            while (len(proofBytesArray) > 0):
                nodeBytes = bytes(proofBytesArray[:32])

                proofNodeData = words_from_little_endian_bytes(nodeBytes)
                isLeftIdx = 0 if proofBytesArray[32] == 1 else 1

                proofNode = ProofNode(proofNodeData, isLeftIdx)
                proof.append(proofNode)

                proofBytesArray = proofBytesArray[33:]

        return proof