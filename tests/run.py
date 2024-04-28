#!/usr/bin/env python3

import scenic
scenic.setDebuggingOptions(verbosity=1, fullBacktrace=True)
from scenic.core.simulators import RejectSimulationException

scenario = scenic.scenarioFromFile('tests/subscenario_req.scenic',
                                   mode2D=True)

scene, _ = scenario.generate(maxIterations=1)

try:
  sim_result = scenario.getSimulator().simulate(
                  scene,
                  maxSteps=600,
                  maxIterations=1,
                  raiseGuardViolations=True
                  )
except RejectSimulationException as e:
  print(f'Caught {e}')
print(sim_result)