import json
import os
import logging
from flask_cors import CORS
from flask import Flask, request, make_response, jsonify, abort
from utils import decrypt_fpe_request, decrypt_request, encrypt_request, exit_error_process, load_schema_file, validate_config_yaml, encrypt_fpe_request
from utils import load_config_yaml,init_dsma_client, load_schema_file, parse_request
from utils import debug_, info_, error_
import base64
import requests

#Logging setup
from logger import logger_init
logger = logging.getLogger("app")

# Load config.yaml
config_yaml = load_config_yaml()
# Load Schema file
SCHEMA = load_schema_file()
# Validate if config.yaml keys are present
validate_config_yaml(config_yaml)

logger_init(config_yaml)
## GLOBALS ##
DEBUG = True if (os.getenv("DEBUG")=="True" or config_yaml['DEBUG'] == True) else False
DEFAULT_PORT = 5000
API_KEY = config_yaml['API_KEY']
DSMA_PORT = config_yaml['DSMA_PORT']

try:
    if len(str(config_yaml['PORT'])) !=0 :
        PORT = config_yaml['PORT']
        info_(logger, 'Using custom port {}'.format(config_yaml['PORT']))
except:
    PORT = DEFAULT_PORT
    info_(logger, 'Using default port {}'.format(DEFAULT_PORT))

try: 
    if len(str(config_yaml['API_ENDPOINT'])) !=0:
        API_ENDPOINT = str(config_yaml['API_ENDPOINT'])
        info_(logger, 'Using DSMA endpoint {}'.format(config_yaml['API_ENDPOINT']))
except:
    error_(logger, 'Missing endpoint for DSMA')
    exit_error_process(1)

api_instances = {}
keyPair = None
pubKey  = None
## END GLOBALS ##


app = Flask(__name__)

# WARNING: Sets CORS for all paths
CORS(app)

def before_first_request():
    response_code, error = init_dsma_client(API_ENDPOINT, DSMA_PORT, API_KEY)
    if response_code != 0:
        print("ERROR: Connection to DSMA is Down")
        error_(logger, error)
        exit_error_process(1)
    info_(logger, "INFO: Connection to DSMA is UP")


@app.errorhandler(404)
def not_found_error(error):
    return make_response(jsonify({'ERROR': 'Resource not found'}), 404)

@app.errorhandler(400)
def illegal_request(error):
    return make_response(jsonify({'ERROR': 'Client issued a malformed or illegal request'}), 400)

@app.errorhandler(500)
def server_error(error):
    return make_response(jsonify({'ERROR': 'Internal server error'}), 500)

@app.route("/helloWorld", methods=['GET'])
def hello():
    return "HelloWorld, 200"


@app.route("/fortanix", methods=['PUT'])
def put_handler():
    try:
        payload_data, message_type = parse_request(request)
        mt_schema = SCHEMA['paymentsmessage']['definitions'][message_type]
        required_fields = mt_schema['required']
        for field in required_fields:
            debug_(logger,payload_data[field])
        transform_enc = mt_schema['transform']["x-encrypted"]['format']
        transform_sig = mt_schema['transform']["x-signed"]['format']
        data_to_sign =  ""
        names = []
        debug_(logger,'transform_enc {}'.format(transform_enc))
        debug_(logger,'transform_sig {}'.format(transform_sig))
        for name, property in mt_schema['properties'].items():
            raw_field = ""
            if isinstance(payload_data[name], str):
                raw_field = payload_data[name]
            else:
                raw_field = json.dumps(payload_data[name])
            debug_(logger,'Name: {}, Field: {}, Value: {}'.format(name, property, raw_field))

            if 'x-encrypted' in property.keys():
                if name not in payload_data.keys():
                    raise ValueError("Missing encryption field in payload: {}".format(name))
                encryption_aes_key_name = config_yaml[property["x-encrypted"]['key']]
                debug_(logger,'Using key {}'.format(encryption_aes_key_name))
                mode = property["x-encrypted"]['mode']
                if 'mode' not in property["x-encrypted"].keys():
                    mode =  "CBC"
               
                debug_(logger,'Using mode {}'.format(mode))
                if mode != "FPE":
                    enc_parts = payload_data[name].split('.')
                    debug_(logger,'enc_parts {}'.format(enc_parts))
                    debug_(logger,'iv  {}'.format((base64.b64encode(enc_parts[0].encode('ascii')).decode('ascii'))))
                    payload = json.dumps({
                        "keyName": encryption_aes_key_name,
                        "alg": "AES",
                        "mode": mode,
                        "cipher": bytes.fromhex(enc_parts[1]).decode('utf-8'),
                        "iv": bytes.fromhex(enc_parts[0]).decode('utf-8')
                     })
                    decResponse = decrypt_request(payload,  API_ENDPOINT +":"+ DSMA_PORT, API_KEY)
                    info_(logger, 'INFO: Response {}'.format(decResponse))
                else:
                    payload = json.dumps({
                        "keyName": encryption_aes_key_name,
                        "alg": "AES",
                        "mode": mode,
                        "cipher": payload_data[name]
                    })
                    decResponse = decrypt_fpe_request(payload,API_ENDPOINT +":"+ DSMA_PORT, API_KEY)
                    info_(logger, 'INFO: Response {}'.format(decResponse))
                if transform_enc == 'replace':
                    if mode == "FPE":
                        payload_data[name] = decResponse['plain']
                        debug_(logger,payload_data[name])
                    else:
                        payload_data[name] = base64.b64decode(decResponse['plain']).decode('utf-8')

                #  Pending sign logic
        return { 'result': base64.b64encode(json.dumps(payload_data).encode()).decode()}
    except KeyError as e:
        print("Error: ", e)
        abort(400)
    except ValueError as e:
        print("Error: ", e)
        abort(400)
    except requests.ConnectionError as e:
        error_(logger, "Unable to connect to DSMA")
        abort(500)

@app.route("/fortanix", methods=['POST'])
def post_handler():
    try:
        payload_data, message_type = parse_request(request)
        mt_schema = SCHEMA['paymentsmessage']['definitions'][message_type]
        required_fields = mt_schema['required']
        for field in required_fields:
            debug_(logger,payload_data[field])
        transform_enc = mt_schema['transform']["x-encrypted"]['format']
        transform_sig = mt_schema['transform']["x-signed"]['format']
        data_to_sign =  ""
        names = []
        debug_(logger,'transform_enc {}'.format(transform_enc))
        debug_(logger,'transform_sig {}'.format(transform_sig))
        for name, property in mt_schema['properties'].items():
            raw_field = ""
            if isinstance(payload_data[name], str):
                raw_field = payload_data[name]
            else:
                raw_field = json.dumps(payload_data[name])
            debug_(logger,'Name: {}, Field: {}, Value: {}'.format(name, property, raw_field))

            if 'x-encrypted' in property.keys():
                if name not in payload_data.keys():
                    raise ValueError("Missing encryption field in payload: {}".format(name))
                encryption_aes_key_name = config_yaml[property["x-encrypted"]['key']]
                debug_(logger,'Using key {}'.format(encryption_aes_key_name))
                mode = property["x-encrypted"]['mode']
                if 'mode' not in property["x-encrypted"].keys():
                    mode =  "CBC"
                message_bytes = payload_data[name].encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')
                debug_(logger,'raw message {} b64 {}'.format(payload_data[name], base64_message))
                debug_(logger,'Using mode {}'.format(mode))
                if mode == "FPE":
                    payload = json.dumps({
                        "keyName": encryption_aes_key_name,
                        "alg": "AES",
                        "mode": mode,
                        "plain": payload_data[name]
                     })
                    encResponse = encrypt_fpe_request(payload, API_ENDPOINT +":"+ DSMA_PORT, API_KEY)
                    info_(logger, 'Response {}'.format(encResponse))
                else:
                    payload = json.dumps({
                        "keyName": encryption_aes_key_name,
                        "alg": "AES",
                        "mode": mode,
                        "plain": base64_message
                     })
                    encResponse = encrypt_request(payload, API_ENDPOINT +":"+ DSMA_PORT, API_KEY)
                    debug_(logger, 'Response {}'.format(encResponse))
                if transform_enc == 'replace':
                    if 'iv' in encResponse.keys(): # non FPE
                        payload_data[name] = encResponse['iv'].encode('utf-8').hex() + "." + encResponse['cipher'].encode('utf-8').hex()
                    else: # FPE
                        payload_data[name] = encResponse['cipher']
                else:
                    info_(logger, "TBD alternative to field -> cipher replacement")

            if 'x-signed' in property.keys():
                if name not in payload_data.keys():
                    raise ValueError("Missing encryption field in payload: {}".format(name))
                if transform_sig == 'payload' or transform_sig == 'extend' or transform_sig == 'complete':
                    data_to_sign = data_to_sign + raw_field
                    debug_(logger,'data to sign {}\n'.format(data_to_sign))
                    #  Pending sign logic
                
        return payload_data
    except KeyError as e:
        print("Error: ", e)
        abort(400)
    except ValueError as e:
        print("Error: ", e)
        abort(400)
    except requests.ConnectionError as e:
        print("Unable to connect to DSMA")
        abort(500)


if __name__ == '__main__':
    info_(logger,"Starting app")
    before_first_request()
    app.run(host='0.0.0.0', debug=DEBUG, port=PORT)
