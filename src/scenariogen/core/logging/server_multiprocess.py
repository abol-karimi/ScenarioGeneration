import os
import multiprocessing
import logging
import logging.config
import logging.handlers
logging_level = logging.DEBUG

queue = None
listener = None

def listener_configurer(filename, filemode):
   root = logging.getLogger()
   h = logging.handlers.RotatingFileHandler(filename,
                                            mode=filemode, # file mode
                                            maxBytes=1024, #10*1024**2, # 10MB
                                            backupCount=10) # 10 files
   f = logging.Formatter('%(asctime)s %(processName)-10s %(name)s %(levelname)-8s %(message)s')
   h.setFormatter(f)
   root.addHandler(h)


def listener_process(q, filename, filemode):
   listener_configurer(filename, filemode)
   while True:
      try:
         record = q.get()
         if record is None:
            break
         logger = logging.getLogger(record.name)
         logger.handle(record)
      except Exception:
         import sys, traceback
         print('Whoops! Problem:', file=sys.stderr)
         traceback.print_exc(file=sys.stderr)


def start(filename, filemode):
   global queue
   global listener

   if os.path.exists(filename) and filemode == 'w':
      os.remove(filename)

   ctx = multiprocessing.get_context('spawn')
   queue = ctx.Queue(-1)
   listener = ctx.Process(target=listener_process,
                           args=(queue, filename, filemode))
   listener.start()


def stop():
   global queue, listener

   queue.put_nowait(None)
   listener.join()