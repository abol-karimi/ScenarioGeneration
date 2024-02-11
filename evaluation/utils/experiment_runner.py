import jsonpickle
from pathlib import Path
from functools import reduce
import time
import multiprocessing
import setproctitle


def generator_process_target(config, generator_state):
  setproctitle.setproctitle('exp-run target')
  generator = config['generator'](config)
  generator.runs(generator_state)


def run(config):
  measurement_period = 60 # seconds
  
  results_file_path = Path(config['results-file'])
  fuzz_inputs_path = Path(config['fuzz-inputs-folder'])
  coverages_path = Path(config['coverages-folder'])
  bugs_path = Path(config['bugs-folder'])
  
  # Decide to resume or start
  if results_file_path.is_file():
    # resume
    coverage_files = set((coverages_path).glob('*'))
    with open(results_file_path, 'r') as f:
      results = jsonpickle.decode(f.read())
    merged_results = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                            results)
    results_fuzz_input_files = reduce(lambda i1,i2: i1.union(i2),
                                      [m['new-fuzz-input-files'] for m in merged_results['measurements']])
    if results_fuzz_input_files != coverage_files:
      print('Cannot resume experiment: the coverage_files in the folder do not match the coverage_files of results.json.')
      print('results_fuzz_input_files - coverage_files:', results_fuzz_input_files - coverage_files)
      print('coverage_files - results_fuzz_input_files:', coverage_files - results_fuzz_input_files)
      exit(1)
    generator_state = results[-1].pop('generator-state')
  else:
    # start
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    coverages_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in coverages_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()

    past_fuzz_input_files = set()
    past_coverage_files = set()
    results = []
    generator_state = None

  # Set up a measurement loop
  measurements = [{'elapsed_time': 0,
                   'new-fuzz-input-files': set(),
                   'new-coverage-files': set(),
                  }]
  
  def measure_progress():
    new_fuzz_input_files = set(fuzz_inputs_path.glob('*')) - past_fuzz_input_files
    new_coverage_files = set(coverages_path.glob('*')) - past_coverage_files
    elapsed_time = time.time()-start_time

    past_fuzz_input_files.update(new_fuzz_input_files)
    past_coverage_files.update(new_coverage_files)
    measurements.append({'elapsed_time': elapsed_time,
                         'new-fuzz-input-files': new_fuzz_input_files,
                         'new-coverage-files': new_coverage_files,
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
                  args=(config, generator_state),
                  name=config['output-folder'])
  
  start_time = time.time()
  p.start()

  while p.is_alive(): # all the implemented generators exit after config['max-total-time']
    measure_progress()
    time.sleep(measurement_period)
