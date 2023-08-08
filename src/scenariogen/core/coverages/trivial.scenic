
model scenic.domains.driving.model

coverage_space = set()
coverage = set()

scenario CoverageScenario():
  setup:
    record final coverage_space as coverage_space
    record final coverage as coverage
   
    monitor CoverageMonitor:
      wait

