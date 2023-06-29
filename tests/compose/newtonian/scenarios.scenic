
model scenic.simulators.newtonian.driving_model

scenario NonegosScenario():
  setup:
    n1 = Car at 170@150,
      with name 'nonego1',
      with blueprint 'vehicle.ford.crown'
    
    n2 = Car at -170@150,
      with name 'nonego2',
      with blueprint 'vehicle.ford.crown'

    cars = [n1, n2]

scenario DummyScenario():
  setup:
    ego = Car at 0@0,
            with name 'dummy',
            with physics False,
            with allowCollisions True,
            with color Color(1, 1, 1),
            with blueprint 'vehicle.ford.crown'

events = []

scenario RecordEvents(cars):
  setup:
    ego = cars[0]
 
    monitor record_events:
      for car in cars:
        events.append(F'Event: {car.name} is spawned!')
      wait

    record final events as events