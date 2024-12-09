from django.contrib import admin
from accounts.models.accounts_model import CustomUser, RolePermission
from auditlog.registry import auditlog


# Register your models here.
# auditlog.register(CustomUser)
# admin.site.unregister(User)
admin.site.register(CustomUser)