
model scenic.domains.driving.model

# python imports
from scenariogen.core.coverages.coverage import Coverage

monitor CoverageMonitor(maxSteps):
  coverage = Coverage()
  wait

