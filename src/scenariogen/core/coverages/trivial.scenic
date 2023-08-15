
model scenic.domains.driving.model

coverage_space = set()
coverage = set()

scenario CoverageScenario():
  setup:
    record initial coverage_space as coverage_space
    record initial coverage as coverage
   
    monitor CoverageMonitor:
      wait

