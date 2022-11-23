from django.shortcuts import render
from rest_framework import generics, viewsets
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema, OpenApiParameter, extend_schema_view
from rest_framework.parsers import FormParser, MultiPartParser
from drf_spectacular.types import OpenApiTypes
from django.contrib.auth.hashers import make_password, check_password
from .serializers import *
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.response import Response
from .utils import *
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib import messages, auth
from django.core.validators import validate_email
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import phonenumbers

# Create your views here.

headerAuthParam = [OpenApiParameter(
    name='Authorizations',
    type=OpenApiTypes.STR,
    location=OpenApiParameter.HEADER,
    description='Authorization',
    required=True,
    default='Bearer ',)]
headerAuthParam1 = [OpenApiParameter(
    name='QuestionType', location=OpenApiParameter.HEADER,
    type=OpenApiTypes.STR,
    required=True,
    enum=['candidate', 'company', 'post'],

), ]


class Register(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)
    parser_classes = (MultiPartParser,)

    @extend_schema(
        tags=['User Authentication'],
        responses={200: AccountResponse,
                   500: CommonErrorResponseSerializer},
        summary='Registration API'
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if Account.objects.filter(email=request.data['email']).exists():
            return error_400(request, code=400, message="Email already exists.")
        if Account.objects.filter(mobile_number=request.data['mobile_number']).exists():
            return error_400(request, code=400, message="Mobile number already exists.")

        try:
            validate_email(request.data['email'])
        except:
            return error_400(request, message="Email address is not valid.", code=400)

        try:
            strmobileNumber = str(
                request.data['country_code'] + request.data['mobile_number'])
            my_number = phonenumbers.parse(strmobileNumber)
        except:
            return error_400(request, code=400, message="Please enter a valid mobile number or country code.")

        if not phonenumbers.is_valid_number(my_number):
            return error_400(request, code=400, message="Please enter a valid mobile number.")
        if len(request.data['mobile_number']) < 7:
            return error_400(request, code=400, message="Please enter a valid mobile number.")
        if len(request.data['mobile_number']) > 15:
            return error_400(request, code=400, message="Please enter a valid mobile number.")
        if len(request.data['password']) > 16:
            return error_400(request, code=400, message="user should not be able to add more than 16 characters from keyboard.")
        try:
            serializer.is_valid(raise_exception=False)
            if serializer.is_valid():
                user = Account.objects.create(
                    email=request.data['email'].lower(),
                    mobile_number=request.data['mobile_number'],
                    password=make_password(request.data['password']),
                    country_code=request.data['country_code'],
                    username=request.data['username'],
                    is_active=True,
                    created_at=int(time.time()),
                    update_at=int(time.time())
                )
                response_data = {
                    'refresh_token': user.tokens()['refresh'],
                    'access_token': user.tokens()['access'],
                }
                return send_response(request, code=200, message=_("Signup success"), data=response_data)
            else:
                error_msg_value = (list(serializer.errors.values())[0][0])
                return error_400(request, code=400, message=(error_msg_value))
        except Exception as e:
            return send_response_validation(request, code=404, message=str(e))


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    parser_classes = (MultiPartParser,)

    @extend_schema(
        tags=['User Authentication'],
        responses={200: UserLoginResponse},
        summary='Login API'
    )
    def post(self, request):
        try:
            validate_email(request.data['email'])
        except:
            return error_400(request, message="Email address is not valid.", code=400)
        try:
            password = request.data['password']
            email = request.data['email'].lower()
            if Account.objects.filter(email=email).exists():
                user = auth.authenticate(email=email, password=password)
                user123 = Account.objects.get(email=email)
                if user123.is_active == False:
                    return error_401(request, message='Account disabled, please contact an administrator.', code=401)
            else:
                return error_401(request, message='Incorrect email address or password.', code=401)
            if user == None:
                return error_401(request, message='Incorrect email address or password.', code=401)

            token = {'refresh': user.tokens()['refresh'],
                     'access': user.tokens()['access']}
            return send_response(request, code=200, message=_("You are logged in successfully"), data=token)
        except Exception as e:
            return error_400(request, code=400, message=str(e))


class CreateProductAPIView(generics.GenericAPIView):
    serializer_class = CreateProductSerializer
    permission_classes = (AllowAny,)
    parser_classes = (MultiPartParser,)

    @extend_schema(
        tags=['Product'],
        parameters=headerAuthParam,
        responses={500: CommonErrorResponseSerializer,
                   200: CommonErrorResponseSerializer},
        summary='Create Product API'
    )
    def post(self, request):
        try:
            if len(request.headers['Authorizations'].split(" ")) == 1:
                return error_401(request, code=401, message="Invalid Token. You are not authenticated to access this endpoint")

            token = request.headers['Authorizations'].split(" ")[1]
            access_token_obj = AccessToken(token)

            user_id = access_token_obj['user_id']
            if not Account.objects.filter(id=user_id).exists():
                return error_404(request, message='Account not found.', code=404)
            user = Account.objects.get(id=user_id)
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid(raise_exception=False):
                Products.objects.create(account_id=user, product_name=request.data['product_name'], price=request.data['price'],
                                        description=request.data['description'], image=request.data['image'], created_at=int(time.time()), update_at=int(time.time()))
                return send_response_validation(request, code=200, message='Product Created Successfully')
            else:
                error_msg_value = (list(serializer.errors.values())[0][0])
                return error_400(request, code=400, message=error_msg_value)
        except Exception as e:
            return error_400(request, code=400, message=str(e))


class DeleteProductAPIView(generics.GenericAPIView):
    permission_classes = (AllowAny,)
    parser_classes = (MultiPartParser,)

    @extend_schema(
        tags=['Product'],
        parameters=headerAuthParam,
        responses={500: CommonErrorResponseSerializer,
                   200: CommonErrorResponseSerializer},
        summary='Delete Product API'
    )
    def delete(self, request, *args, **kwargs):
        try:
            if len(request.headers['Authorizations'].split(" ")) == 1:
                return error_401(request, code=401, message="Invalid Token. You are not authenticated to access this endpoint")

            token = request.headers['Authorizations'].split(" ")[1]
            access_token_obj = AccessToken(token)

            user_id = access_token_obj['user_id']
            if not Account.objects.filter(id=user_id).exists():
                return error_404(request, message='Account not found.', code=404)
            user = Account.objects.get(id=user_id)
            if not Products.objects.filter(id=self.kwargs['id']).exists():
                return error_404(request, message='Product not found.', code=404)
            Products.objects.filter(id=self.kwargs['id']).delete()
            return send_response_validation(request, code=200, message='Product Deleted Successfully')
        except Exception as e:
            if str(e) in 'Token is invalid or expired':
                return error_400(request, code=400, message=str(e))
            return error_400(request, code=400, message=list(e)[0])


class UpdateProductAPIView(generics.GenericAPIView):
    serializer_class = UpdateProductSerializer
    parser_classes = (MultiPartParser,)
    permission_classes = (AllowAny,)

    @extend_schema(
        tags=['Product'],
        parameters=headerAuthParam,
        responses={500: CommonErrorResponseSerializer,
                   200: CommonErrorResponseSerializer},
        summary='Create Product API'
    )
    def patch(self, request, *args, **kwargs):
        try:
            if len(request.headers['Authorizations'].split(" ")) == 1:
                return error_401(request, code=401, message="Invalid Token. You are not authenticated to access this endpoint")

            token = request.headers['Authorizations'].split(" ")[1]
            access_token_obj = AccessToken(token)

            user_id = access_token_obj['user_id']
            if not Account.objects.filter(id=user_id).exists():
                return error_404(request, message='Account not found.', code=404)
            user = Account.objects.get(id=user_id)
            if not Products.objects.filter(id=self.kwargs['id']).exists():
                return error_401(request, message='Product not found.', code=401)
            product = Products.objects.get(id=self.kwargs['id'])
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid(raise_exception=False):
                if request.data.get('product_name') != None and len(request.data['product_name']) != 0:
                    product.product_name = request.data.get('product_name')
                if request.data.get('price') != None and len(request.data['price']) != 0:
                    product.price = request.data.get('price')
                if request.data.get('description') != None and len(request.data['description'])!= 0:
                    product.description = request.data.get('description')
                if request.data.get('image') != None and len(request.data['image'])!=0:
                    product.image = request.data['image']
                product.save()
                return send_response_validation(request, code=200, message='Product Updated Successfully')
            else:
                error_msg_value = (list(serializer.errors.values())[0][0])
                return error_400(request, code=400, message=error_msg_value)
        except Exception as e:
            if str(e) in 'Token is invalid or expired':
                return error_400(request, code=400, message=str(e))
            return error_400(request, code=400, message=list(e)[0])

class RetrieveProductAPIView(generics.GenericAPIView):
    serializer_class = RetrieveProductSerializer
    parser_classes = (MultiPartParser,)
    permission_classes = (AllowAny,)

    @extend_schema(
        tags=['Product'],
        parameters=headerAuthParam,
        responses={500: CommonErrorResponseSerializer,
                   200: RetrieveResponse},
        summary='Retrieve Product API'
    )
    def get(self, request, *args, **kwargs):
        try:
            if len(request.headers['Authorizations'].split(" ")) == 1:
                return error_401(request, code=401, message="Invalid Token. You are not authenticated to access this endpoint")

            token = request.headers['Authorizations'].split(" ")[1]
            access_token_obj = AccessToken(token)
            user_id = access_token_obj['user_id']
            if not Account.objects.filter(id=user_id).exists():
                return error_404(request, message='Account not found.', code=404)
            user = Account.objects.get(id=user_id)
            products = Products.objects.filter(account_id=user)
            product_lista = []
            for row in products:
                product_lista.append({
                    'id': row.id,
                    'account_id': row.account_id.id,
                    'product_name': row.product_name,
                    'price': row.price,
                    'description': row.description,
                    'image': str(row.image)
                })
            print(product_lista)
            return send_response_validation(request, code=200, message=product_lista)
        except Exception as e:
            if str(e) in 'Token is invalid or expired':
                return error_400(request, code=400, message=str(e))
            return error_400(request, code=400, message=list(e)[0])

def handler404(request, exception):
    return render(request, '404-found.html', status=404)

def handler500(request):
    return render(request, '500-internal.html', status=500)
