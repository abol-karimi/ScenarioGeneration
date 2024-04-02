import pickle
import logging
import logging.handlers
import socketserver
import struct
import threading

class LogRecordStreamHandler(socketserver.StreamRequestHandler):
    """Handler for a streaming logging request.

    This basically logs the record using whatever logging policy is
    configured locally.
    """

    def handle(self):
        """
        Handle multiple requests - each expected to be a 4-byte length,
        followed by the LogRecord in pickle format. Logs the record
        according to whatever policy is configured locally.
        """
        while True:
            chunk = self.connection.recv(4)
            if len(chunk) < 4:
                break
            slen = struct.unpack('>L', chunk)[0]
            chunk = self.connection.recv(slen)
            while len(chunk) < slen:
                chunk = chunk + self.connection.recv(slen - len(chunk))
            obj = self.unPickle(chunk)
            record = logging.makeLogRecord(obj)
            self.handleLogRecord(record)

    def unPickle(self, data):
        return pickle.loads(data)

    def handleLogRecord(self, record):
        name = record.name
        logger = logging.getLogger(name)
        logger.handle(record)


class Logger:
    def __init__(self, filename, filemode='a'):
        logging.basicConfig(
            level=logging.DEBUG,
            filename=filename,
            filemode=filemode,
            format='%(relativeCreated)5d %(name)-15s %(levelname)-8s %(message)s'
        )
        self.server = socketserver.TCPServer(('localhost', logging.handlers.DEFAULT_TCP_LOGGING_PORT),
                                             LogRecordStreamHandler)

    def start(self):
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        print("Logging server loop running in thread:", self.server_thread.name)
    
    def stop(self):
        self.server.server_close()
        print('Stopped the logging server.')