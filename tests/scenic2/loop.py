#!/usr/bin/env python3.8
import scenic
import scenic.core.errors as _errors
_errors.showInternalBacktrace = True   # see comment in errors module
del _errors


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