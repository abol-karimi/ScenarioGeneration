model scenic.simulators.newtonian.driving_model

scenario EgoScenario():
  setup:
    car = Car at 0@0,
      with name 'ego',
      with blueprint 'vehicle.ford.crown',
      with behavior FollowLaneBehavior()
    cars = [car]