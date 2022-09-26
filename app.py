import json
import os
import logging
from flask_cors import CORS
from flask import Flask, request, make_response, jsonify, abort
from utils import encrypt_request, exit_error_process, load_schema_file, validate_config_yaml, encrypt_fpe_request
from utils import load_config_yaml,init_dsma_client, load_schema_file
from controllers import parse_request
import base64

# Load config.yaml
config_yaml = load_config_yaml()
# Load Schema file
SCHEMA = load_schema_file()
# Validate if config.yaml keys are present
validate_config_yaml(config_yaml)

## GLOBALS ##
DEBUG = True if (os.getenv("DEBUG")=="True" or config_yaml['DEBUG'] == True) else False
DEFAULT_PORT = 5000
DEFAULT_API_ENDPOINT = 'https://apps.sdkms.fortanix.com'
API_KEY = config_yaml['API_KEY']
DSMA_PORT = config_yaml['DSMA_PORT']

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

def info_(data):
    print(data)
    app.logger.info(data)

def error_(data):
    app.logger.error(data)
##End logging setup

app = Flask(__name__)

# WARNING: Sets CORS for all paths
CORS(app)

def before_first_request():
    response_code, error = init_dsma_client(API_ENDPOINT, DSMA_PORT, API_KEY)
    if response_code != 0:
        print("ERROR: Connection to DSMA is Down")
        error_(error)
        exit_error_process(1)
    print("INFO: Connection to DSMA is UP")


@app.errorhandler(404)
def not_found_error(error):
    return make_response(jsonify({'ERROR': 'Resource not found'}), 404)

@app.errorhandler(400)
def illegal_request(error):
    return make_response(jsonify({'ERROR': 'Client issued a malformed or illegal request'}), 400)


@app.route("/helloWorld", methods=['GET'])
def hello():
    return "HelloWorld, 200"


@app.route("/fortanix", methods=['POST'])
def post_handler():
    try:
        payload_data, message_type = parse_request(request)
        mt_schema = SCHEMA['paymentsmessage']['definitions'][message_type]
        required_fields = mt_schema['required']
        for field in required_fields:
            debug_(payload_data[field])
        transform_enc = mt_schema['transform']["x-encrypted"]['format']
        transform_sig = mt_schema['transform']["x-signed"]
        data_to_sign =  None
        names = []
        debug_("transform_enc", transform_enc)
        for name, property in mt_schema['properties'].items():
            raw_field = None
            if isinstance(payload_data[name], str):
                raw_field = payload_data[name]
            else:
                raw_field = json.dumps(payload_data[name])
            debug_('Name: {}, Field: {}, Value: {}'.format(name, property, raw_field))

            if 'x-encrypted' in property.keys():
                if name not in payload_data.keys():
                    raise ValueError("Missing encryption field in payload: {}".format(name))
                encryption_aes_key_name = config_yaml[property["x-encrypted"]['key']]
                debug_('Using key {}'.format(encryption_aes_key_name))
                mode = property["x-encrypted"]['mode']
                if 'mode' not in property["x-encrypted"].keys():
                    mode =  "CBC"
                message_bytes = payload_data[name].encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')
                debug_('raw message {} b64 {}'.format(payload_data[name], base64_message))
                debug_('Using mode {}'.format(mode))
                if mode == "FPE":
                    payload = json.dumps({
                        "keyName": encryption_aes_key_name,
                        "alg": "AES",
                        "mode": mode,
                        "plain": payload_data[name]
                     })
                    encResponse = encrypt_fpe_request(payload, API_ENDPOINT +":"+ DSMA_PORT, API_KEY)
                else:
                    payload = json.dumps({
                        "keyName": encryption_aes_key_name,
                        "alg": "AES",
                        "mode": mode,
                        "plain": base64_message
                     })
                    encResponse = encrypt_request(payload, API_ENDPOINT +":"+ DSMA_PORT, API_KEY)

                if transform_enc == 'replace':
                    if 'iv' in encResponse.keys(): # non FPE
                        payload_data[name] = encResponse['iv'].encode('utf-8').hex() + "." + encResponse['cipher'].encode('utf-8').hex()
                    else: # FPE
                        payload_data[name] = encResponse['cipher']
                else:
                    print("TBD alternative to field -> cipher replacement")
        return payload_data
    except KeyError as e:
        print("Error: ", e)
        abort(400)
    except ValueError as e:
        print("Error: ", e)
        abort(400)

    return 'OK'


if __name__ == '__main__':
    info_("INFO: Starting App on port {}".format(PORT))
    before_first_request()
    app.run(host='0.0.0.0', debug=DEBUG, port=PORT)
