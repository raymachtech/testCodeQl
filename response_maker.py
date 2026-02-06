import logging
from flask import jsonify, make_response

def responseMaker(data, status, statuscode, header, contenttype="application/json"):
    responseBody = {header: data}
    
    response = make_response(jsonify(responseBody), statuscode)
    response.headers["Content-Type"] = contenttype
    response.status_code = statuscode
    
    return response

def error_response(error_message="An internal error occurred", status_code=500, exception=None, context=None):
    if exception:
        if context:
            logging.error(f"{context}: {exception}", exc_info=True)
        else:
            logging.error(f"Error: {exception}", exc_info=True)
    return jsonify({
        "error": error_message,
        "message": "Please contact support if this persists",
        "code": status_code
    }), status_code

def log_error(exception, context=None):
    if context:
        logging.error(f"{context}: {exception}", exc_info=True)
    else:
        logging.error(f"Error: {exception}", exc_info=True)
