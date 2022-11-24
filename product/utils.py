from django.http import JsonResponse

def send_response(request, code, message, data):

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message, 'responseData': data})
    response.status_code = 200
    return response

def send_response_validation(request, code, message):

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message})
    response.status_code = 200
    return response

def error_404(request, code, message):

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message})
    response.status_code = 404
    return response


def error_422(request, message):

    response = JsonResponse(data={'message': message})
    response.status_code = 422
    return response


def error_500(request, code, message):
    message = 'An internal error occurred. An administrator has been notified. '

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message})
    response.status_code = 500
    return response


def error_400(request, code, message):

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message})
    response.status_code = 400
    return response


def error_402(request, code, message):

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message})
    response.status_code = 402
    return response

def error_401(request, code, message):

    response = JsonResponse(
        data={'responseCode': code, 'responseMessage': message})
    response.status_code = 401
    return response

from uuid import UUID

def is_valid_uuid(uuid_to_test, version=4):
    """
    Check if uuid_to_test is a valid UUID.
    
     Parameters
    ----------
    uuid_to_test : str
    version : {1, 2, 3, 4}
    
     Returns
    -------
    `True` if uuid_to_test is a valid UUID, otherwise `False`.
    
     Examples
    --------
    >>> is_valid_uuid('c9bf9e57-1685-4c89-bafb-ff5af830be8a')
    True
    >>> is_valid_uuid('c9bf9e58')
    False
    """
    
    try:
        uuid_obj = UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test