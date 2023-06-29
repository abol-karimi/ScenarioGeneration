model scenic.simulators.carla.model

scenario EgoScenario():
  setup:
    ego = Car at 0@0,
      with name 'ego',
      with blueprint 'vehicle.ford.crown'
