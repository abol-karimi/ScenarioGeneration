import jsonpickle
from pathlib import Path
from functools import reduce
from timeloop import Timeloop
from datetime import timedelta
import time

def run(config):
  generator = config['generator'](config)

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
    fuzzer_state = results[-1].pop('generator-state')
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
    fuzzer_state = None

  # Set up a measurement loop
  measurements = [{'exe_time': 0,
                   'elapsed_time': 0,
                   'new_event_files': set(),
                  }]
  tl = Timeloop()
  period = 120 # seconds
  @tl.job(interval=timedelta(seconds=period))
  def measure_progress():
    new_event_files = set(events_path.glob('*')) - past_event_files
    past_event_files.update(new_event_files)
    measurements.append({'exe_time': period,
                         'elapsed_time': time.time()-start_time,
                         'new_event_files': new_event_files,
                        })
    partial_result = [{'measurements': measurements,
                      'generator-state': None
                      }]
    with open(results_file_path, 'w') as f:
      f.write(jsonpickle.encode(results+partial_result, indent=1))

    print(f'\nMeasurement recorded!\n')

  tl.start(block=False)
  start_time = time.time()
  try:
    fuzzer_state = generator.runs(fuzzer_state)
  except Exception as e:
    print(f'Exception of type {type(e)} in Atheris: {e}.')
    raise e
  finally:
    tl.stop()
    print(f'Measurement thread stopped.')    

  # Measure one last time in case the the time-loop thread missed some new results
  measure_progress()
  
  results.append({'measurements': measurements,
                  'generator-state': fuzzer_state
                  })

  with open(results_file_path, 'w') as f:
    f.write(jsonpickle.encode(results, indent=1))