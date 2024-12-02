from django.contrib import admin
from accounts.models.accounts_model import CustomUser, RolePermission
from auditlog.registry import auditlog
from django.contrib.auth.models import User

# Register your models here.
# auditlog.register(CustomUser)
# admin.site.unregister(User)
admin.site.register(User, CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'role', 'job_title', 'department')
    search_fields = ('username', 'role', 'job_title')

@admin.register(RolePermission)
class RolePermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'role', 'table_name', 'fields_allowed')
    search_fields = ('role', 'table_name')