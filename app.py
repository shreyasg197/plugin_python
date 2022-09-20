import os
import time
import json
import config
import random
import logging
from flask_cors import CORS
from flask import Flask, request, make_response, jsonify, abort


config.DEBUG   = True if (os.getenv("DEBUG")=="yes") else False

## GLOBALS ##
keyPair = None
pubKey  = None
## END GLOBALS ##

##Logging setup
if(config.DEBUG):
    logging.basicConfig(filename= config.FLASK_LOG_PATH, level=logging.DEBUG)
else:
    logging.basicConfig(filename= config.FLASK_LOG_PATH, level=logging.INFO)

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
    config.keyPair, config.pubKey = init_keypair()
    config.API_KEY = os.getenv()

@app.errorhandler(404)
def not_found_error(error):
    return make_response(jsonify({'error': 'Resource not found'}), 404)

@app.errorhandler(400)
def illegal_request(error):
    return make_response(jsonify({'error': 'Client issued a malformed or illegal request'}), 404)


@app.route("/helloWorld", methods=['POST'])
def hello():
    return dummy_func()


def dummy_func():
    return "HelloWorld"

if __name__ == '__main__':
    print("runnning on ort 5000")
    app.run(host='0.0.0.0', debug=False, port=5000)