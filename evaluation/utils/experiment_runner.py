import jsonpickle
from pathlib import Path
from functools import reduce
import time
import multiprocessing
import setproctitle
import logging
import sys

from scenariogen.core.fuzzing.fuzzers.atheris import AtherisFuzzer
from scenariogen.core.logging.client import configure_logger, TextIOBaseToLog
import scenariogen.core.logging.server as log_server


def generator_process_target(config, generator_state, log_queue):
  setproctitle.setproctitle(config['generator'].__name__)
  configure_logger(log_queue)
  logger = logging.getLogger(f'{__name__}.target')
  # capture stdout and stderr to the logs as well
  sys.stdout = TextIOBaseToLog(logger.debug)
  sys.stderr = TextIOBaseToLog(logger.warning)
  
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
  output_path = Path(config['output-folder'])
  if output_path.is_dir():
    logging.error('Output-folder already exists, cannot continue.')
    return

  results_file_path = Path(config['results-file'])
  fuzz_inputs_path = Path(config['fuzz-inputs-folder'])
  coverages_path = Path(config['coverages-folder'])
  events_path = Path(config['events-folder'])
  bugs_path = Path(config['bugs-folder'])
  logs_path = Path(config['logs-folder'])

  fuzz_inputs_path.mkdir(parents=True, exist_ok=True)
  coverages_path.mkdir(parents=True, exist_ok=True)
  events_path.mkdir(parents=True, exist_ok=True)
  bugs_path.mkdir(parents=True, exist_ok=True)
  logs_path.mkdir(parents=True, exist_ok=True)

  logging.info('Experiment-runner starting to log to file...')
  log_server.start(logs_path / 'trial.log', filemode='w')
  logger = logging.getLogger(__name__)

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

  ctx = multiprocessing.get_context('spawn')
  p = ctx.Process(target=generator_process_target,
                  args=(config, generator_state, log_server.queue),
                  name=config['output-folder'])
  
  start_time = time.time()
  p.start()

  while p.is_alive(): # the generator is expected to return after config['max-total-time']
    p.join(config['measurement-period']-(time.time()-start_time-measurements[-1]['elapsed-time']))
    measure_progress(fuzz_inputs_path,
                      past_fuzz_input_files,
                      coverages_path,
                      past_coverage_files,
                      start_time,
                      measurements,
                      results_file_path,
                      results,
                      config)
  
  logger.info(f'Generator process exited with code: {p.exitcode}')

  log_server.stop()
  logging.info("Stopped experiment-runner's logger.")