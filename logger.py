from datetime import datetime
from distutils.command.config import config
import time
import os

## Init logging start 
import logging
import logging.handlers

def logger_init(config_yaml):
    NO_FILE_LOGS = config_yaml['NO_FILE_LOGS']
    FLASK_LOG_PATH = config_yaml['FLASK_LOG_PATH']
    DEBUG = True if (os.getenv("DEBUG")=="True" or config_yaml['DEBUG'] == True) else False
    filename = "flask.log"

    ## get logger
    logger = logging.getLogger() ## root logger

    if DEBUG:
        logger.setLevel(logging.DEBUG)
        print('\nLog level set to DEBUG')
    else:
        logger.setLevel(logging.INFO)
        print('\nLog level set to INFO')

    # File handler
    if NO_FILE_LOGS == False:
        logfilename = datetime.now().strftime("%Y%m%d_%H%M%S") + f"_{filename}"
        print("Log file at " + FLASK_LOG_PATH + logfilename + "\n")
        file = logging.handlers.TimedRotatingFileHandler(f"{FLASK_LOG_PATH}{logfilename}", when="midnight", interval=1)
        #fileformat = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        fileformat = logging.Formatter("%(asctime)s [%(levelname)s]: %(name)s: %(message)s")
        file.setLevel(logging.DEBUG)
        file.setFormatter(fileformat)

    # Stream handler
    stream = logging.StreamHandler()
    streamformat = logging.Formatter("%(asctime)s [%(levelname)s]: %(name)s: %(message)s")
    if DEBUG:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    stream.setFormatter(streamformat)

    # Adding all handlers to the logs
    logger.addHandler(file)
    logger.addHandler(stream)
