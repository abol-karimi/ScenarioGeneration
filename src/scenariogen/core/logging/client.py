import logging
import logging.handlers
import scenariogen.core.logging.server as log_server
import sys

def configure_logger(queue):
    logging.captureWarnings(True)
    log_server.queue = queue
    qh = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.addHandler(qh)
    root.setLevel(logging.DEBUG)


class TextIOBaseToLog:
  def __init__(self, level):
    self.level = level

  def write(self, message):
    m = message.strip()
    if m != '':
      self.level(m)

  def flush(self):
    self.level(sys.stderr)
  
  def isatty(self):
    return False