import logging
import logging.handlers


def configure_logger(queue):
    qh = logging.handlers.QueueHandler(queue)
    root = logging.getLogger()
    root.addHandler(qh)
    root.setLevel(logging.DEBUG)
