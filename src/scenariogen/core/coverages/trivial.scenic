
model scenic.domains.driving.model

# python imports
from scenariogen.core.coverages.coverage import Coverage

scenario EvaluateCoverageScenario():
  setup:
    coverage = Coverage()

