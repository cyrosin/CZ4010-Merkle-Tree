from pure_python_blake3 import *
from blake3 import blake3
from naiveAuth.proofNode import ProofNode

class Prover:
    def __init__(self, data, isPath=False):
        if len(data) == 0:
            raise Exception("Prover must be instantiated with len(data) > 0")
            
        self.data_chunks = []

        if isPath:
            # If provided with a list of filepaths, preprocess them by hashing them
            if isinstance(data, (list, tuple)):
                data = self._hashfiles(data)
                while data:
                    self.data_chunks.append(data[:1024])
                    data = data[1024:]
            else:
                with open(data, 'rb') as f:
                    while chunk := f.read(1024):
                        self.data_chunks.append(chunk)
        else:
            if type(data) != bytes:
                data = bytes(data)
            while data:
                self.data_chunks.append(data[:1024])
                data = data[1024:]
    
    def respondToChallenge(self, challengedIdx):
        proofBytes = self.generateProof(challengedIdx)
        return proofBytes

    def generateProof(self, challengedIdx):
        challenged_chunk_idx = challengedIdx % len(self.data_chunks)

        proof = [] # Store the proof to be sent
        node_hashes = [] # Store the hashes at each level of the tree
        getNeighbour = True # The first 2 proof nodes will be on the same level

        # If there is only 1 chunk, then we append to the proof the hash of that chunk, rather than the chaining values
        if len(self.data_chunks) == 1:
            hasher = Hasher()
            hasher.update(self.data_chunks[0])
            rootHash = hasher.finalize().hex()
            proof.append(ProofNode(rootHash, None))
            proofBytes = self._proofToBytes(proof)
            return proofBytes

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
            if challenged_chunk_idx == len(node_hashes) - 1:
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

        proofBytes = self._proofToBytes(proof)

        return proofBytes

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

    def _proofToBytes(self, proof):
        if len(proof) == 1:
            byteArray = bytearray.fromhex(proof[0].data)
            byteArray.append(2)
        else:
            byteArray = bytearray(b'')
            for proofNode in proof:
                for wordIdx in range(8):
                    byteArray.extend(proofNode.data[wordIdx].to_bytes(4, byteorder='little'))
                isLeftIdx = 1 if proofNode.left else 0
                byteArray.append(isLeftIdx)
    
        return bytes(byteArray)
