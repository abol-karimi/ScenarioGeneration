import os
import multiprocessing
import threading
import logging
import logging.config
import logging.handlers
from logging.handlers import RotatingFileHandler

queue = None
thread = None


class IncrementingRotatingFileHandler(RotatingFileHandler):
    def doRollover(self):
        self.stream.close()
        root, ext = os.path.splitext(self.baseFilename)
        i = 1
        while True:
            new_file = f"{root}_{i}{ext}"
            if not os.path.exists(new_file):
                os.rename(self.baseFilename, new_file)
                break
            i += 1
        self.mode = 'w'
        self.stream = self._open()


def logger_thread(q):
    server_logger = logging.getLogger(__name__)
    server_logger.info('Log-server thread started!')

    while True:
        record = q.get()
        if record is None:
            server_logger.info('Stopping the log-server thread...')
            break
        logger = logging.getLogger(record.name)
        logger.handle(record)


def start(filename, filemode):
    global queue, thread

    if os.path.exists(filename) and filemode == 'w':
        os.remove(filename)
    
    ctx = multiprocessing.get_context('spawn')
    queue = ctx.Queue()
    d = {
        'version': 1,
        'formatters': {
            'detailed': {
                'class': 'logging.Formatter',
                'format': '%(asctime)s %(name)s %(levelname)s %(message)s',
                'datefmt': '%H:%M:%S',
            }
        },
        'handlers': {
            'file': {
                'class': 'scenariogen.core.logging.server.IncrementingRotatingFileHandler',
                'filename': filename,
                'mode': filemode,
                'maxBytes': 10*1024*1024, # 10MB
                'backupCount': 1000, # 1000 files
                'formatter': 'detailed',
            },
        },
        'root': {
            'level': 'DEBUG',
            'handlers': ['file']
        },
        'catureWarnings': True,
    }
    logging.config.dictConfig(d)
    thread = threading.Thread(target=logger_thread, args=(queue,))
    thread.start()


def stop():
    global queue, thread

    queue.put(None)
    thread.join()

    logger = logging.getLogger(__name__)
    logger.info('Shutting down the log server...')
    logging.shutdown()