#!/usr/bin/env python3.8
import scenic

config = {}
config['steps'] = 30
config['timestep'] = 0.05
config['intersection'] = 'intersection396'
config['carla_map'] = 'Town05'
config['arrival_distance'] = 4

# Run the scenario on the seed
params = {'carla_map': config['carla_map'],
          'map': f"/home/carla/CarlaUE4/Content/Carla/Maps/OpenDrive/{config['carla_map']}.xodr",
          'timestep': config['timestep'],
          'render': True,
          'config': config
          }

scenic_scenario = scenic.scenarioFromFile(
    'test_compose.scenic',
    scenario='TestScenario',
    params=params)

# Load the map if necessary
# client = carla.Client('127.0.0.1', 2000)
# loaded_map = client.get_world().get_map().name
# if loaded_map != config['carla_map']:
#     client.load_world(config['carla_map'])

scene, _ = scenic_scenario.generate(maxIterations=1)
simulator = scenic_scenario.getSimulator()
sim_result = simulator.simulate(
                scene,
                maxSteps=config['steps'],
                maxIterations=1,
                raiseGuardViolations=True
                )

# How many objects in the scenario?
for p in sim_result.trajectory[0]:
    print(p)
