
from pure_python_blake3 import *
from blake3 import blake3
from proposedAuth.proofNode import ProofNode
import secrets
import sys
import math
import os

import time

class Verifier:
    def __init__(self, data, isPath=False):
        hasher = blake3() # Using the blake3 (PyO3) package speeds up the hashing

        start = time.time()
        if isPath:
            with open(data, 'rb') as f:
                hasher.update(f.read())
                fileSize = os.path.getsize(data)
                self.num_chunks = fileSize // 1024
                # if fileSize % 1024 != 0:
                #     self.num_chunks += 1

                # while chunk := f.read(fileSize // 10):
                #     hasher.update(chunk)
        else:
            if (type(data) != bytes):
                data = bytes(data)
            hasher.update(data)
            
            self.num_chunks = len(data) // 1024
            if len(data) % 1024 != 0:
                self.num_chunks += 1
        
        self.root_hash = hasher.digest().hex()
        end = time.time()

        print('done')
        print(f'{end - start} s')
        
        self.tree_height = math.ceil(math.log2(self.num_chunks))   

    def issueChallenge(self):
        challengeIdx = secrets.randbelow(sys.maxsize)

        # In theory could be any positive integer, but memory errors occur when the proofLength requested
        # is too large. For reference, a 1 PB of data would create a tree of height ~40, thus generating a
        # proof length below 1024 sounds reasonable
        proofLength = secrets.randbelow(1024) 

        self.proofLength = proofLength
        return challengeIdx, proofLength
        
    def verify(self, proofBytes):
        restoredProofBytes = self._restoreProof(proofBytes)
        proof = self.bytesToProofNodes(restoredProofBytes)

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

    def _restoreProof(self, proofBytes):
        HASHLENGTH_BITS = 264

        proofBytesArray = bytearray(proofBytes)
        prefixBytesLength = (self.proofLength - self.tree_height - 2) * HASHLENGTH_BITS // 8
        proofBytesArray = proofBytesArray[prefixBytesLength:] # Remove prefix bytes
        self.proofLength = None # Do not need the proof length anymore

        rootHashBytes = bytearray.fromhex(self.root_hash)
        rootHashBytes.append(2)
        rootHashBytes = bytes(rootHashBytes)

        mask = int.from_bytes(proofBytesArray[-33:], byteorder='big') ^ int.from_bytes(rootHashBytes, byteorder='big')
        proofBytesArray = proofBytesArray[:-33]

        restoredProofBytes = bytearray(b'')
        while(len(proofBytesArray) > 0):
            proofNodeBin = int.from_bytes(proofBytesArray[:33], byteorder='big')
            obfuscatedProofNodeBin = proofNodeBin ^ mask
            obfuscatedProofNodeBytes = obfuscatedProofNodeBin.to_bytes(33, byteorder='big')
            restoredProofBytes.extend(obfuscatedProofNodeBytes)
            proofBytesArray = proofBytesArray[33:]
        
        restoredProofBytes = bytes(restoredProofBytes)

        return restoredProofBytes
