from rest_framework import serializers
from .models import *
import re

mobile = (
    ("android", "android"),
    ("ios", "ios"),
)


class RegisterSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)

    class Meta:
        model = Account
        fields = ('username', 'email', 'mobile_number',
                  'country_code','password',)

    def __init__(self, *args, **kwargs):
        super(RegisterSerializer, self).__init__(*args, **kwargs)
        self.fields['email'].error_messages['blank'] = u'Email cannot be blank!'
        self.fields['email'].error_messages['required'] = u'The email field is required'
        self.fields['mobile_number'].error_messages['blank'] = u'Mobile number cannot be blank!'
        self.fields['mobile_number'].error_messages['required'] = u'The mobile_number field is required'
        self.fields['password'].error_messages['blank'] = u'Password cannot be blank!'
        self.fields['password'].error_messages['required'] = u'The password field is required'

    def validate(self, attrs):
        regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"

        if not (re.fullmatch(regex, attrs.get('password', ''))):
            raise serializers.ValidationError(
                "'Password should contains minimum 8 characters. Allow at least 1 digit, 1 special characters, 1 uppercase letter & 1 lowercase letter.'")

        return attrs


class AccountSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)
    access_token = serializers.CharField(required=False)


class AccountResponse(serializers.Serializer):
    responseCode = serializers.IntegerField()
    responseMessage = serializers.CharField()
    responseData = AccountSerializer(required=False)


class LoginResponseSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=False)
    access_token = serializers.CharField(required=False)


class UserLoginResponse(serializers.Serializer):
    """Your data serializer, define your fields here."""
    responseCode = serializers.IntegerField()
    responseMessage = serializers.CharField()
    responseData = LoginResponseSerializer(required=False)


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(
        max_length=128, min_length=8, write_only=True, required=True)


class CommonErrorResponseSerializer(serializers.Serializer):
    responseCode = serializers.IntegerField()
    responseMessage = serializers.CharField()


class CreateProductSerializer(serializers.ModelSerializer):

    class Meta:
        model = Products
        fields = ('product_name', 'price', 'description', 'image',)

    def __init__(self, *args, **kwargs):
        super(CreateProductSerializer, self).__init__(*args, **kwargs)
        self.fields['product_name'].error_messages['blank'] = u'Product name cannot be blank!'
        self.fields['product_name'].error_messages['required'] = u'The product field is required'
        self.fields['price'].error_messages['blank'] = u'Price number cannot be blank!'
        self.fields['price'].error_messages['required'] = u'The price field is required'
        self.fields['description'].error_messages['blank'] = u'Description cannot be blank!'
        self.fields['description'].error_messages['required'] = u'The description field is required'

class BlankableDecimalField(serializers.DecimalField):
    """
    We wanted to be able to receive an empty string ('') for a decimal field
    and in that case turn it into a None number
    """
    def to_internal_value(self, data):
        if data == '':
            return None

        return super(BlankableDecimalField, self).to_internal_value(data)

class UpdateProductSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(required=False)
    price = BlankableDecimalField(required=False, max_digits=10, decimal_places=2)
    description = serializers.CharField(required=False)
    image = serializers.CharField(required=False)
    class Meta:
        model = Products
        fields = ('product_name', 'price', 'description', 'image',)
        
class RetrieveProductSerializer(serializers.Serializer):
    id = serializers.CharField(required=False)
    account_id = serializers.CharField(required=False)
    product_name = serializers.CharField(required=False)
    price = BlankableDecimalField(required=False, max_digits=5, decimal_places=2)
    description = serializers.CharField(required=False)
    image = serializers.CharField(required=False)

class RetrieveResponse(serializers.Serializer):
    responseCode = serializers.IntegerField()
    responseMessage = serializers.CharField()
    responseData = RetrieveProductSerializer(required=False)

class ListProductSerializer(serializers.Serializer):
    id = serializers.CharField(required=False)
    account_id = serializers.CharField(required=False)
    product_name = serializers.CharField(required=False)
    price = BlankableDecimalField(required=False, max_digits=5, decimal_places=2)
    description = serializers.CharField(required=False)
    image = serializers.CharField(required=False)

class ListResponse(serializers.Serializer):
    responseCode = serializers.IntegerField()
    responseMessage = serializers.CharField()
    responseData = RetrieveProductSerializer(many=True)
