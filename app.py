import os
import time
import json
from unittest.mock import DEFAULT
import config
import random
import logging
from flask_cors import CORS
from flask import Flask, request, make_response, jsonify, abort
from utils import exit_error_process, validate_config_yaml, load_config_yaml
from controllers import parse_request

# DSM IMPORTS
import sdkms.v1

from sdkms.v1.rest import ApiException
from sdkms.v1.models.cipher_mode import CipherMode
from sdkms.v1.models.object_type import ObjectType
from sdkms.v1.models.sobject_descriptor import SobjectDescriptor
# from sdkms.v1.models.mac_generate_request import MacGenerateRequest
# from sdkms.v1.models.mac_verify_request import MacVerifyReques

# Load config.yaml
config_yaml = load_config_yaml()
# Validate if config.yaml keys are present
validate_config_yaml(config_yaml)

## GLOBALS ##
DEBUG = True if (os.getenv("DEBUG")=="True" or config_yaml['DEBUG'] == True) else False
DEFAULT_PORT = 5000
DEFAULT_API_ENDPOINT = 'https://apps.sdkms.fortanix.com'
DEFAULT_VERIFY_SSL = True
API_KEY = config_yaml['API_KEY']
try:
    if len(str(config_yaml['PORT'])) !=0 :
        PORT = config_yaml['PORT']
        print("INFO: Using custom port", config_yaml['PORT'])
except:
    PORT = DEFAULT_PORT
    print("INFO: Using default port 5000")

try: 
    if len(str(config_yaml['API_ENDPOINT'])) !=0:
        API_ENDPOINT = str(config_yaml['API_ENDPOINT'])
        print("INFO: Using custom endpoint", config_yaml['API_ENDPOINT'])
except:
    API_ENDPOINT = DEFAULT_API_ENDPOINT
    print("INFO: Using default endpoint", DEFAULT_API_ENDPOINT)

try:
    if len(str(config_yaml['VERIFY_SSL'])) !=0:
        VERIFY_SSL = str(config_yaml['VERIFY_SSL'])
        print("INFO: Setting VERIFY_SSL to", config_yaml['VERIFY_SSL'])
except:
    VERIFY_SSL = DEFAULT_VERIFY_SSL
    print("INFO: Setting default VERIFY_SSL to", DEFAULT_VERIFY_SSL)

ca_certificate = None
api_instances = {}
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
    init_sdkms_client(API_KEY)

def init_sdkms_client(api_key):
    parts = api_key.split(':')
    if len(parts) != 2:
        print('Invalid API key provided')
        exit(1)
    config = sdkms.v1.configuration.Configuration()
    config.host = API_ENDPOINT
    config.username = parts[0]
    config.password = parts[1]
    config.verify_ssl = VERIFY_SSL
    config.debug = DEBUG
    if ca_certificate:
      config.ssl_ca_cert = ca_certificate

    client = sdkms.v1.ApiClient(configuration=config)
    client.configuration.debug = cl_args.debug

    auth_instance = sdkms.v1.AuthenticationApi(api_client=client)
    auth = auth_instance.authorize()
    print_debug('Auth credentials: {} {}'.format(config.username,
                                                   config.password))
    print_debug(auth)

    config.api_key['Authorization'] = auth.access_token
    config.api_key_prefix['Authorization'] = 'Bearer'

    api_instances['auth'] = auth_instance
    api_instances['sobjects'] = sdkms.v1.SecurityObjectsApi(
        api_client=client)
    api_instances['protect'] = sdkms.v1.EncryptionAndDecryptionApi(
        api_client=client)
    api_instances['digest'] = sdkms.v1.DigestApi(
        api_client=client)
    api_instances['trust'] = sdkms.v1.SignAndVerifyApi(
        api_client=client)


@app.errorhandler(404)
def not_found_error(error):
    return make_response(jsonify({'ERROR': 'Resource not found'}), 404)

@app.errorhandler(400)
def illegal_request(error):
    return make_response(jsonify({'ERROR': 'Client issued a malformed or illegal request'}), 400)


@app.route("/helloWorld", methods=['GET'])
def hello():
    init_sdkms_client(API_KEY)
    return "HelloWorld, 200"


@app.route("/fortanix", methods=['POST'])
def post_handler():
    try:
        payload, message_type = parse_request(request)
        debug_(message_type)
    except KeyError:
        abort(400)
    return 'OK'


if __name__ == '__main__':
    print("Starting App on port", PORT)
    app.run(host='0.0.0.0', debug=DEBUG, port=PORT)
