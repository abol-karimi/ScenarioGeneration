#!/usr/bin/env python3.8

import scenic

scenario = scenic.scenarioFromFile('tests/road_direction.scenic',
                                   mode2D=True)

scene, _ = scenario.generate(maxIterations=1)
sim_result = scenario.getSimulator().simulate(
                scene,
                maxSteps=600)