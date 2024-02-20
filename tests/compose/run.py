#!/usr/bin/env python3.8
import scenic

config = {
    'carla-map': 'Town05',
    'intersection_uid': 'intersection1930',
    'timestep': 0.05,
    'render': True,
    'ego': True,
    'ego-module': 'tests.compose.newtonian.ego',
    'simulator': 'newtonian',
}

params = {'carla-map': config['carla-map'],
          'map': f"/home/ak/Scenic/assets/maps/CARLA/{config['carla-map']}.xodr",
          'render': config['render'],
          'timestep': config['timestep'],
          'config': config,
          }

SUT_scenario = scenic.scenarioFromFile(
                    f"tests/compose/{config['simulator']}/SUT.scenic",
                    scenario='SUTScenario',
                    params=params,
                    cacheImports=False)

print(f'Initializing the scenario...')
scene, _ = SUT_scenario.generate(maxIterations=1)
simulator = SUT_scenario.getSimulator()

print(f'Simulating the scenario...')
sim_result = simulator.simulate(
                scene,
                maxSteps=20,
                maxIterations=1,
                raiseGuardViolations=True)

events = sim_result.records['events']
for e in events:
    print(e)