from pure_python_blake3 import *
import random

class ProofNode:
    def __init__(self, nodeCV, left):
        self.data = nodeCV 
        self.left = left


class Prover:
    def __init__(self, data):
        self.data_chunks = []

        if (type(data) != bytes) :
            data = bytes(data)
        while data:
            self.data_chunks.append(data[:1024])
            data = data[1024:]

    def generateProof(self):
        challenged_chunk_idx = random.choice(len(self.data_chunks))
        hashers = [] # Initial hashes of data chunks
        proof = [] # Store the proof to be sent
        node_hashes = [] # Store the hashes at each level of the tree
        getNeighbour = True # The first 2 proof nodes will be on the same level

        if challenged_chunk_idx != len(node_hashes) - 1 or len(node_hashes) % 2 == 0:
            proofNode = ProofNode(node_hashes[challenged_chunk_idx])
            proof.append(proofNode)
        
        while len(node_hashes) > 1:
            # Find the required sibling index
            required_chunk_idx = None
            if challenged_chunk_idx == len(hashers) - 1:
                if len(node_hashes) % 2 != 1:
                    required_chunk_idx = challenged_chunk_idx - 1
                else:
                    appendProof = False
            else:
                if challenged_chunk_idx % 2 == 0:
                    required_chunk_idx = challenged_chunk_idx + 1
                else:
                    required_chunk_idx = challenged_chunk_idx - 1

            if appendProof:
                proof.append(node_hashes[challenged_chunk_idx])
                if getNeighbour:
                    proof.append(node_hashes[required_chunk_idx])
                    getNeighbour = False

            # Combine node hashes to get parents
            parent_node_hashes = []

            for i in range(0, len(node_hashes), 2):
                if i == len(node_hashes) - 1 and len(node_hashes) % 2 == 1:
                    parent_node_hashes.append(node_hashes[i])
                else:
                    parent_node_hashes.append(parent_cv(node_hashes[i], node_hashes[i + 1], IV, PARENT))
            node_hashes = parent_node_hashes
            if required_chunk_idx:
                challenged_chunk_idx = required_chunk_idx // 2
            else:
                challenged_chunk_idx = challenged_chunk_idx // 2

        [1,2,3,4,5,6,7]
        [[1_2], [3_4], [5_6], [7]]
        [[1234], [567]]
        [1234567]

        if first then + 1
        if last then - 1
        else 
            if even then + 1
            if odd - 1

        []