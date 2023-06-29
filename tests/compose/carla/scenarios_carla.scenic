
model scenic.simulators.carla.model

scenario NonegosScenario():
  setup:
    ego = Car at 170@150,
      with name 'nonego',
      with blueprint 'vehicle.ford.crown'
    cars = [ego]

scenario DummyScenario():
  setup:
    ego = Car at 0@0,
            with name 'dummy',
            with physics False,
            with allowCollisions True,
            with color Color(1, 1, 1),
            with blueprint 'vehicle.ford.crown'

scenario RecordEvents(cars):
  setup:
    ego = cars[0]
    events = []
    record final events as events
 
    monitor record_events:
      events.append('Event 0')
      wait
