#!/usr/bin/python
import sys
import yaml
import requests
import logging
import json 
import base64
from requests.exceptions import HTTPError

logger = logging.getLogger(__name__)

def entered_fn(logger, function_name):
    logger.debug("Entered function %s", str(function_name))

def exit_fn(logger, function_name):
    logger.debug("Exiting function %s", str(function_name))

def debug_(logger, data):
    logger.debug(data)

def info_(logger, data):
    logger.info(data)

def error_(logger, data):
    logger.error(data)

def load_config_yaml():
    try:        
        with open('config.yaml', 'r') as file:
            config_yaml = yaml.safe_load(file)
            return config_yaml
    except Exception as e: 
        error_(logger, "config.yaml not found".format(e))
        exit_error_process(2)

def load_schema_file():
    try:
        with open('mt-schema.json', 'r') as file:
            schema = json.load(file)
            info_(logger, "Schema loaded successfully")
            return schema
    except Exception as e: 
        error_(logger, "mt-schema.json not found", e)
        exit_error_process(2)


# Check for keys in the yaml
def validate_config_yaml(config_yaml):
    info_(logger, "Verifying config.yaml")
    keys = ['DEBUG', 'NO_FILE_LOGS', 'API_KEY', 'API_ENDPOINT', 'DSMA_PORT']
    try:
        for key in keys:
            if not key in config_yaml:
                raise KeyError(key)
        # If NO_FILE_LOGS is set to False, the user must provide a LOG PATH
        if config_yaml['NO_FILE_LOGS'] == False:
            if not "FLASK_LOG_PATH" in config_yaml:
                raise KeyError("FLASK_LOG_PATH")
        # Validate API KEY from DSM
        # validate_api_key(config_yaml['API_KEY'])
    except KeyError as error:
        error_(logger, "Key not found in config.yaml", error)
        exit_error_process(1)
    except Exception as error:
        error_(logger, error)
        exit_error_process(1)

def init_dsma_client(api_endpoint, dsma_port, api_key):
    try:
        response = requests.get(api_endpoint + ":" + dsma_port)
    except Exception as error:
        return -1, error
    return 0, None

def parse_request(request):
    if request.headers.get('Content-Type') == 'application/json':
        payload = request.get_json()
    else:
        payload = json.loads(request.data)
    debug_(logger, base64.b64decode(payload['payload']))
    return json.loads(base64.b64decode(payload['payload'])), payload['message_type']

def encrypt_request(payload, url, api_key):
    url = url + "/encrypt"
    info_(logger, '{} {}'.format(url, payload))
    headers={"Content-Type": "application/json", "apiKey": api_key}
    response = requests.post(url, data=payload, headers=headers)
    return response.json()

def encrypt_fpe_request(payload, url, api_key):
    url = url + "/tokenize"
    info_(logger, '{} {}'.format(url, payload))
    headers={"Content-Type": "application/json", "apiKey": api_key}
    response = requests.post(url, data=payload, headers=headers)
    return response.json()

def decrypt_request(payload, url, api_key):
    url = url + "/decrypt"
    info_(logger, '{} {}'.format(url, payload))
    headers={"Content-Type": "application/json", "apiKey": api_key}
    response = requests.post(url, data=payload, headers=headers)
    return response.json()

def decrypt_fpe_request(payload, url, api_key):
    url = url + "/detokenize"
    info_(logger, '{} {}'.format(url, payload))
    headers={"Content-Type": "application/json", "apiKey": api_key}
    response = requests.post(url, data=payload, headers=headers)
    return response.json()

# Check if api key is 164 length 
def validate_api_key(api_key):
    if len(api_key) != 164:
        raise Exception ("Invalid Api Key")

# Exit with the given errno
def exit_error_process(errno):
    sys.exit(errno)