import logging
import logging.handlers
import scenariogen.core.logging.server as log_server

def configure_logger(queue):
    logging.captureWarnings(True)
    log_server.queue = queue
    qh = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.addHandler(qh)
    root.setLevel(logging.DEBUG)
