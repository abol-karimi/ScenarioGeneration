
model scenic.domains.driving.model

# python imports
from scenariogen.core.coverages.coverage import Coverage

coverage = Coverage()

scenario CoverageScenario():
  setup:
   
    monitor CoverageMonitor:
      wait

