import jsonpickle
from pathlib import Path
from functools import reduce
import time
import multiprocessing
import setproctitle
import logging

from scenariogen.core.fuzzing.fuzzers.atheris import AtherisFuzzer
from scenariogen.core.logging.client import configure_logger


def generator_process_target(config, generator_state, log_queue):
  setproctitle.setproctitle(config['generator'].__name__)
  configure_logger(log_queue)
  
  if config['generator'] is AtherisFuzzer:
    atheris_output_path = Path(config['atheris-output-folder'])
    atheris_output_path.mkdir(parents=True, exist_ok=True)
    for path in atheris_output_path.glob('*'):
      path.unlink()

  generator = config['generator'](config)
  final_state = generator.runs(generator_state)
  with open(f"{config['output-folder']}/generator-state.json", 'w') as f:
    f.write(jsonpickle.encode(final_state, indent=1))


def measure_progress(fuzz_inputs_path,
                      past_fuzz_input_files,
                      coverages_path,
                      past_coverage_files,
                      start_time,
                      measurements,
                      results_file_path,
                      results,
                      config):
  logger = logging.getLogger(__name__)

  new_fuzz_input_files = set(fuzz_inputs_path.glob('*')) - past_fuzz_input_files
  new_coverage_files = set(coverages_path.glob('*')) - past_coverage_files
  elapsed_time = time.time()-start_time

  past_fuzz_input_files.update(new_fuzz_input_files)
  past_coverage_files.update(new_coverage_files)
  measurements.append({'elapsed-time': elapsed_time,
                        'new-fuzz-input-files': new_fuzz_input_files,
                        'new-coverage-files': new_coverage_files,
                      })
  partial_result = [{'measurements': measurements}]
  with open(results_file_path, 'w') as f:
    f.write(jsonpickle.encode(results+partial_result, indent=1))

  logger.info(f'''Measurement recorded!
                \t Elapsed time: {elapsed_time}
                \t output-folder: {config['output-folder']}'''
              )


def run(config):
  logger = logging.getLogger(__name__)
  measurement_period = 60 # seconds
  
  generator_state_path = Path(config['output-folder'])/'generator-state.json'
  results_file_path = Path(config['results-file'])
  fuzz_inputs_path = Path(config['fuzz-inputs-folder'])
  coverages_path = Path(config['coverages-folder'])
  events_path = Path(config['events-folder'])
  bugs_path = Path(config['bugs-folder'])
  
  # Decide to resume or start
  if generator_state_path.is_file():
    # resume
    fuzz_input_files = set((fuzz_inputs_path).glob('*'))
    with open(results_file_path, 'r') as f:
      results = jsonpickle.decode(f.read())
    merged_results = reduce(lambda r1,r2: {'measurements': r1['measurements']+r2['measurements']},
                            results)
    results_fuzz_input_files = reduce(lambda i1,i2: i1.union(i2),
                                      [m['new-fuzz-input-files'] for m in merged_results['measurements']])
    if results_fuzz_input_files != fuzz_input_files:
      logger.error(f'''Cannot resume experiment: the fuzz_input_files in the folder do not match the fuzz_input_files of results.json!
                      results_fuzz_input_files - fuzz_input_files: {results_fuzz_input_files - fuzz_input_files}
                      fuzz_input_files - results_fuzz_input_files: {fuzz_input_files - results_fuzz_input_files}
                    ''')
      exit(1)
   
    past_fuzz_input_files = results_fuzz_input_files
    past_coverage_files = reduce(lambda i1,i2: i1.union(i2),
                                      [m['new-coverage-files'] for m in merged_results['measurements']])
    with open(f"{config['output-folder']}/generator-state.json", 'r') as f:
      generator_state = jsonpickle.decode(f.read())
    
  else:
    # start
    fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
    coverages_path.mkdir(parents=True, exist_ok=True)
    events_path.mkdir(parents=True, exist_ok=True)
    bugs_path.mkdir(parents=True, exist_ok=True)
    for path in fuzz_inputs_path.glob('*'):
      path.unlink()
    for path in coverages_path.glob('*'):
      path.unlink()
    for path in events_path.glob('*'):
      path.unlink()
    for path in bugs_path.glob('*'):
      path.unlink()

    past_fuzz_input_files = set()
    past_coverage_files = set()
    results = []
    generator_state = None

  # Set up a measurement loop
  measurements = [{'elapsed-time': 0,
                   'new-fuzz-input-files': set(),
                   'new-coverage-files': set(),
                  }]
  
  logger.info(f"Now running experiment: {config['output-folder']}")

  import scenariogen.core.logging.server as log_server
  ctx = multiprocessing.get_context('spawn')
  p = ctx.Process(target=generator_process_target,
                  args=(config, generator_state, log_server.queue),
                  name=config['output-folder'])
  
  start_time = time.time()
  p.start()

  while p.is_alive(): # the generator is expected to exit after config['max-total-time']
    p.join(measurement_period-(time.time()-start_time-measurements[-1]['elapsed-time']))
    measure_progress(fuzz_inputs_path,
                      past_fuzz_input_files,
                      coverages_path,
                      past_coverage_files,
                      start_time,
                      measurements,
                      results_file_path,
                      results,
                      config)

