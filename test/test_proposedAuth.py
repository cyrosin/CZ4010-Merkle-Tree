import unittest
import secrets
import os

from proposedAuth.verifier import Verifier
from proposedAuth.prover import Prover


class TestProposedAuth(unittest.TestCase):
    @unittest.skip
    def test_4chunk_message(self):
        message = secrets.token_bytes(4096)

        v = Verifier(message)
        p = Prover(message)

        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)
    @unittest.skip
    def test_5chunk_message(self):
        message = secrets.token_bytes(5120)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)
    @unittest.skip
    def test_6chunk_message(self):
        message = secrets.token_bytes(6144)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)
    @unittest.skip
    def test_7chunk_message(self):
        message = secrets.token_bytes(7168)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)
    @unittest.skip
    @unittest.expectedFailure
    def test_empty_message(self):
        message = secrets.token_bytes(0)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)
    @unittest.skip
    def test_short_message(self):
        message = secrets.token_bytes(1)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)

    def test_file_auth(self):
        dirname = os.path.dirname(__file__)
        filename = os.path.join(dirname, '../data/dummy.exe')
 
        v = Verifier(filename, isPath=True)
        p = Prover(filename, isPath=True)
    
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)


    # Implement testing for corrupted messages