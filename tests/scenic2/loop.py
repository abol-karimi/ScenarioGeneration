#!/usr/bin/env python3
import scenic
scenic.setDebuggingOptions(verbosity=2, fullBacktrace=True)

seconds = 20
timestep = .05
render = False

def simulate(scenic_file):
    scenario = scenic.scenarioFromFile(
                    scenic_file,
                    params={'timestep': timestep,
                            'render': render,
                            },
                    cacheImports=False
                    )
    scene, _ = scenario.generate(maxIterations=1)
    simulator = scenario.getSimulator()
    sim_result = simulator.simulate(
                        scene,
                        maxSteps=int(seconds // timestep),
                        maxIterations=1,
                        raiseGuardViolations=True
                        ) 
    return sim_result

res1 = simulate('tests/scenic2/dynamic.scenic')
res2 = simulate('tests/scenic2/dynamic.scenic')