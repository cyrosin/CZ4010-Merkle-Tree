from pure_python_blake3 import *
import random

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
        hashers = []
        proof = []
        for chunk in self.data_chunks:
            hashers.append(Hasher(chunk))

        proof.append(hashers[challenged_chunk_idx].chunk_state.output().chaining_value())
        
        while len(hashers) > 1:
            if challenged_chunk_idx == 0:
                required_chunk_idx = challenged_chunk_idx + 1
            elif challenged_chunk_idx == len(hashers) - 1:
                required_chunk_idx = challenged_chunk_idx - 1
            else:
                if challenged_chunk_idx % 2 == 0:
                    required_chunk_idx = challenged_chunk_idx + 1
                else:
                    required_chunk_idx = challenged_chunk_idx - 1

            proof.append(hashers[required_chunk_idx].chunk_state.output().chaining_value())
            
            chainedHashers = []
            for i in range(0, len(hashers), 2):
                chainedHashers.append(hasher)
            



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