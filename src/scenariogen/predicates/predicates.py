min_perceptible_time = 0.5

import clingo
from scenariogen.core.events import term_to_time

class TemporalOrder:
  def lessThan(self, S, T):
    lt = min_perceptible_time < term_to_time(T.name) - term_to_time(S.name)
    return clingo.Number(1) if lt else clingo.Number(0)

  def equal(self, S, T):
    eq = abs(term_to_time(S.name) - term_to_time(T.name)) < min_perceptible_time
    return clingo.Number(1) if eq else clingo.Number(0)
