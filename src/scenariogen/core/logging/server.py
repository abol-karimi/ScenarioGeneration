import os
import multiprocessing
import threading
import logging
import logging.config
import logging.handlers
logging_level = logging.DEBUG

queue = None
thread = None


def logger_thread(q):
    while True:
        record = q.get()
        if record is None:
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
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': filename,
                'mode': filemode,
                'maxBytes': 10*1024*1024, # 10MB
                'backupCount': 100, # 100 files
                'formatter': 'detailed',
            },
        },
        'root': {
            'level': 'DEBUG',
            'handlers': ['file']
        },
    }
    logging.config.dictConfig(d)
    thread = threading.Thread(target=logger_thread, args=(queue,))
    thread.start()


def stop():
    global queue, thread

    queue.put(None)
    thread.join()