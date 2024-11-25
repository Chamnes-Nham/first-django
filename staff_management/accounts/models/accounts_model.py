from django.db import models
from django.contrib.auth.models import AbstractUser
from auditlog.registry import auditlog


# Create your models here.
class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('staff', 'Staff'),
       
    ]
    
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="staff")
    job_title = models.CharField(max_length=100, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.username
    
class RolePermission(models.Model):
    role = models.CharField(max_length=10, choices=CustomUser.ROLE_CHOICES)
    table_name = models.CharField(max_length=100)
    fields_allowed = models.JSONField(default=list)

    def __str__(self):
        return f"{self.role} - {self.table_name}"
    
class AuditLog(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)

    def __str__(self):
        return f'{self.user} - {self.action} at {self.timestamp}'
    
auditlog.register(CustomUser)

