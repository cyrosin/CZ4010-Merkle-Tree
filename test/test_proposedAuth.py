import unittest
import secrets

from proposedAuth.verifier import Verifier
from proposedAuth.prover import Prover

class TestNaiveAuth(unittest.TestCase):
    def test_4chunk_message(self):
        message = secrets.token_bytes(4096)

        v = Verifier(message)
        p = Prover(message)

        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)
    
    def test_5chunk_message(self):
        message = secrets.token_bytes(5120)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)

    def test_6chunk_message(self):
        message = secrets.token_bytes(6144)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)

    def test_7chunk_message(self):
        message = secrets.token_bytes(7168)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)

    @unittest.expectedFailure
    def test_empty_message(self):
        message = secrets.token_bytes(0)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)

    def test_short_message(self):
        message = secrets.token_bytes(1)

        v = Verifier(message)
        p = Prover(message)
        
        challengeIdx, requiredProofLength = v.issueChallenge()
        proofBytes = p.respondToChallenge(challengeIdx, requiredProofLength)
        result = v.verify(proofBytes)
        self.assertEqual(result, True)