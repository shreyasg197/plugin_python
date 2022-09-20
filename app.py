import os
import time
import json
import config
import random
import logging
from flask_cors import CORS
from flask import Flask, request, make_response, jsonify, abort
from utils import exit_error_process, validate_config_yaml, load_config_yaml

# Load config.yaml
config_yaml = load_config_yaml()
# Validate if config.yaml keys are present
validate_config_yaml(config_yaml)

## GLOBALS ##
DEBUG = True if (os.getenv("DEBUG")=="True" or config_yaml['DEBUG'] == True) else False
API_KEY = config_yaml['API_KEY']
keyPair = None
pubKey  = None
## END GLOBALS ##

##Logging setup
try:
    if(config_yaml['NO_FILE_LOGS'] == True):
        if(DEBUG):
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
    else:
        if(DEBUG):
            logging.basicConfig(filename= config_yaml['FLASK_LOG_PATH'], level=logging.DEBUG)
        else:
            logging.basicConfig(filename= config_yaml['FLASK_LOG_PATH'], level=logging.INFO)
except KeyError as error:
    print("ERROR: Key not found in config.yaml", error)
    exit_error_process(1)

def entered_func(function_name):
    app.logger.debug("Entered function %s", str(function_name))

def exit_func(function_name):
    app.logger.debug("Exiting function %s", str(function_name))

def debug_(data):
    app.logger.debug(data)

def error_(data):
    app.logger.error(data)
##End logging setup

app = Flask(__name__)

# WARNING: Sets CORS for all paths
CORS(app)

@app.before_first_request
def before_first_request():
    # something to do before the first request TBD

@app.errorhandler(404)
def not_found_error(error):
    return make_response(jsonify({'error': 'Resource not found'}), 404)

@app.errorhandler(400)
def illegal_request(error):
    return make_response(jsonify({'error': 'Client issued a malformed or illegal request'}), 404)


@app.route("/helloWorld", methods=['GET'])
def hello():
    entered_func("hello")
    return dummy_func()


def dummy_func():
    return "HelloWorld"

if __name__ == '__main__':
    print("Starting App on port")
    app.run(host='0.0.0.0', debug=DEBUG, port=5000)
