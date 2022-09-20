#!/usr/bin/python
import sys
import yaml

def load_config_yaml():
    try:        
        with open('config.yaml', 'r') as file:
            config_yaml = yaml.safe_load(file)
            return config_yaml
    except Exception as e: 
        print("ERROR: config.yaml not found", e)
        exit_error_process(2)

# Check for keys in the yaml
def validate_config_yaml(config_yaml):
    print("INFO: Verifying config.yaml")
    keys = ['DEBUG', 'NO_FILE_LOGS', 'API_KEY']
    try:
        for key in keys:
            if not key in config_yaml:
                raise KeyError(key)
        # If NO_FILE_LOGS is set to False, the user must provide a LOG PATH
        if config_yaml['NO_FILE_LOGS'] == False:
            if not "FLASK_LOG_PATH" in config_yaml:
                raise KeyError("FLASK_LOG_PATH")
        # Validate API KEY from DSM
        validate_api_key(config_yaml['API_KEY'])
    except KeyError as error:
        print("ERROR: Key not found in config.yaml", error)
        exit_error_process(1)
    except Exception as error:
        print("ERROR: ", error)
        exit_error_process(1)


    
# Check if api key is 164 length 
def validate_api_key(api_key):
    if len(api_key) != 164:
        raise Exception ("Invalid Api Key")

# Exit with the given errno
def exit_error_process(errno):
    sys.exit(errno)