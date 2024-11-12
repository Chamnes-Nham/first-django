from django.contrib import admin
from accounts.models import CustomUser
from auditlog.registry import auditlog

# Register your models here.
auditlog.register(CustomUser)