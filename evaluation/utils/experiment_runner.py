import jsonpickle
from pathlib import Path
from functools import reduce
from datetime import timedelta
import time
import multiprocessing

# from scenariogen.core.fuzzing.runner import SUTRunner


def generator_process_target(config, generator_state):
  generator = config['generator'](config)
  generator.runs(generator_state)


def run(config):
  measurement_period = 60 # seconds
  
  results_file_path = Path(config['results-file'])
  fuzz_inputs_path = Path(config['fuzz-inputs-folder'])
  events_path = Path(config['events-folder'])
  bugs_path = Path(config['bugs-folder'])
  
  # Decide to resume or start
  if results_file_path.is_file():
    # resume
    event_files = set((events_path).glob('*'))
    with open(results_file_path, 'r') as f:
      results = jsonpickle.decode(f.read())
    merged_results = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                            results)
    results_event_files = reduce(lambda i1,i2: i1.union(i2),
                            [m['new_event_files'] for m in merged_results['measurements']])
    if results_event_files != event_files:
      print('Cannot resume Atheris: the event_files in the folder do not match the event_files of results.json.')
      print('results_event_files - event_files:', results_event_files - event_files)
      print('event_files - results_event_files:', event_files - results_event_files)
      exit(1)
    generator_state = results[-1].pop('generator-state')
  else:
    # start
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    events_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in events_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()

    past_event_files = set()
    results = []
    generator_state = None

  # Set up a measurement loop
  measurements = [{'elapsed_time': 0,
                   'new_event_files': set(),
                  }]
  
  def measure_progress():
    new_event_files = set(events_path.glob('*')) - past_event_files
    elapsed_time = time.time()-start_time

    past_event_files.update(new_event_files)
    measurements.append({'elapsed_time': elapsed_time,
                         'new_event_files': new_event_files,
                        })
    partial_result = [{'measurements': measurements}]
    with open(results_file_path, 'w') as f:
      f.write(jsonpickle.encode(results+partial_result, indent=1))

    print(f'\nMeasurement recorded!')
    print(f'\t Elapsed time: {elapsed_time}')
    print(f"\t output-folder: {config['output-folder']}")

  print(f"Now running experiment: {config['output-folder']}")
 
  ctx = multiprocessing.get_context('spawn')
  p = ctx.Process(target=generator_process_target,
                  name=f"{config['output-folder']}",
                  args=(config, generator_state))
  
  start_time = time.time()
  p.start()

  while p.is_alive(): # all the implemented generators exit after config['max-total-time']
    measure_progress()
    time.sleep(measurement_period)
