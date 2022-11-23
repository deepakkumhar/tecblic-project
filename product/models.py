import uuid
import time
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.
class Account(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True, db_index=True,)
    mobile_number = models.CharField(max_length=20,unique=True)
    country_code = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    username = models.CharField(unique=False, max_length=150)
    created_at = models.IntegerField()
    update_at = models.IntegerField()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

class Products(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account_id = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='products_user_id')
    product_name = models.CharField(max_length=200)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField()
    image = models.ImageField(upload_to='productimage/')
    created_at = models.IntegerField()
    update_at = models.IntegerField()