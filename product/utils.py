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