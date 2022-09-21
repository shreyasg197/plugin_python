#!/usr/bin/python
import json
import base64
import logging
from utils import debug_mod

logger = logging.getLogger(__name__)
# def validate_request_fields(request):

def parse_request(request):
    if request.headers.get('Content-Type') == 'application/json':
        payload = request.get_json()
    else:
        payload = json.loads(request.data)
    debug_mod(logger, payload)
    return json.loads(base64.b64decode(payload['payload']))