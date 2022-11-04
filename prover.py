from pure_python_blake3 import *
import random

class ProofNode:
    def __init__(self, nodeData, index):
        self.data = nodeData 
        self.left = self._isLeft(index)

    def _isLeft(self, index):
        return (index % 2 == 0) if index else None

class Prover:
    def __init__(self, data):
        self.data_chunks = []

        if (type(data) != bytes) :
            data = bytes(data)
        # if (len(data) < 64):
        #     data = data + (64 - len(data)) * b"0"
        while data:
            self.data_chunks.append(data[:1024])
            data = data[1024:]

    def generateProof(self):
        print(self.data_chunks)
        challenged_chunk_idx = random.randint(0, len(self.data_chunks) - 1)
        # print(challenged_chunk_idx)
        # challenged_chunk_idx = 0
        hashers = [] # Initial hashes of data chunks
        proof = [] # Store the proof to be sent
        node_hashes = [] # Store the hashes at each level of the tree
        getNeighbour = True # The first 2 proof nodes will be on the same level

        # If there is only 1 chunk, then we append to the proof the hash of that chunk, rather than the chaining values
        if len(self.data_chunks) == 1:
            hasher = Hasher()
            hasher.update(self.data_chunks[0])
            rootHash = hasher.finalize().hex()
            proof.append(ProofNode(rootHash, None))
            return proof

        for idx in range(len(self.data_chunks)):
            hasher = Hasher()
            hasher.chunk_state = ChunkState(IV, idx, 0)
            hasher.update(self.data_chunks[idx])
            node_hashes.append(hasher.chunk_state.output().chaining_value())

        while len(node_hashes) > 1:
            # Find the required sibling index
            required_chunk_idx = None
            appendProof = True
            # If the current challenged chunk is the last node and there is an odd number of current nodes,
            # then we don't append the node hash and simply concat child nodes
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

            print("node_hashes", node_hashes)
            if appendProof:
                proofNode = ProofNode(node_hashes[required_chunk_idx], required_chunk_idx)
                proof.append(proofNode)
                if getNeighbour:
                    challengedNode = ProofNode(node_hashes[challenged_chunk_idx], challenged_chunk_idx)
                    proof.append(challengedNode)
                    getNeighbour = False

            # Combine node hashes to get parents
            parent_node_hashes = []

            for i in range(0, len(node_hashes), 2):
                if i == len(node_hashes) - 1 and len(node_hashes) % 2 == 1:
                    parent_node_hashes.append(node_hashes[i])
                else:
                    parent_node_hashes.append(parent_cv(node_hashes[i], node_hashes[i + 1], IV, PARENT))
            node_hashes = [x[:] for x in parent_node_hashes]
            if required_chunk_idx:
                challenged_chunk_idx = required_chunk_idx // 2
            else:
                challenged_chunk_idx = challenged_chunk_idx // 2

        # for proofNode in proof:
        #     print(proofNode.data)

        return proof

        # [1,2,3,4,5,6,7]
        # [[1_2], [3_4], [5_6], [7]]
        # [[1234], [567]]
        # [1234567]

        # if first then + 1
        # if last then - 1
        # else 
        #     if even then + 1
        #     if odd - 1

        # []