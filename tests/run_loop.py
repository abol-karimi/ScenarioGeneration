#!/usr/bin/env python3

import scenic
scenic.setDebuggingOptions(verbosity=2, fullBacktrace=True)

scenario = scenic.scenarioFromFile('tests/random.scenic',
                                   mode2D=True,
                                   params={'render':False
                                           })
simulator = scenario.getSimulator()

for i in range(2):
    print(f'Iteration {i}:')
    scene, _ = scenario.generate(maxIterations=50)
    sim_result = simulator.simulate(
                    scene,
                    maxSteps=100,
                    maxIterations=1
                    )
