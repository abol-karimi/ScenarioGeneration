#!/usr/bin/env python3.8

import scenic
from scenic.simulators.newtonian import NewtonianSimulator

scenario = scenic.scenarioFromFile('tests/scenic3/scenario.scenic', mode2D=True)

scene, _ = scenario.generate(maxIterations=20)
simulator = NewtonianSimulator()
sim_result = simulator.simulate(
                scene,
                timestep=0.05,
                maxSteps=100
                )
print(sim_result.records)