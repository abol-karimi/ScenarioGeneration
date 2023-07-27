from collections import Counter

class Coverage:
 
  def __init__(self, predicates=set()):
    self.coverage = Counter(predicates)
  
  def __sub__(self, other):
     return self.coverage - other.coverage
  
  def __iadd__(self, other):
     self.coverage += other.coverage 

  def __len__(self):
    return len(self.coverage)
  
  def is_novel_to(self, other):
     return len(self.coverage.keys() - other.coverage.keys()) == 0