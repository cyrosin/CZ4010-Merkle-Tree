class ProofNode:
    def __init__(self, nodeData, index):
        self.data = nodeData 
        self.left = self._isLeft(index)

    def _isLeft(self, index):
        return ((index % 2 == 0) if index != None else None)