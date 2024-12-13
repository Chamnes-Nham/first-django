from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from auditlog.registry import auditlog
from safedelete.models import SafeDeleteModel, SOFT_DELETE
from safedelete.managers import SafeDeleteManager
from django.utils.timezone import now
from django.conf import settings


class CustomUserManager(SafeDeleteManager, BaseUserManager):
    def get_by_natural_key(self, username):
        return self.get(username=username)
    
    def create_user(self, username, email, password=None, **extra_fields):
        """
        Creates and returns a regular user.
        """
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """
        Creates and returns a superuser.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, **extra_fields)



class CustomUser(AbstractUser, SafeDeleteModel):

    _safedelete_policy = SOFT_DELETE
    ROLE_CHOICES = [
        ("admin", "Admin"),
        ("staff", "Staff"),
    ]

    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default="staff")
    job_title = models.CharField(max_length=100, blank=True, null=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)

    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deleted_user",
        help_text="Who deleted this record",
    )
    deleted_at = models.DateTimeField(
        null=True, blank=True, help_text="Time when user was deleted."
    )

    objects = CustomUserManager()
    all_objects = models.Manager()
    not_deleted_objects = SafeDeleteManager()

    def soft_delete(self, user=None, **kwargs):
        if user:
            self.deleted_by = user

        self.deleted_at = now()
        super(CustomUser, self).delete(**kwargs)

    def restore(self, **kwargs):
      
        if self.deleted is not None:
            self.deleted = None
            self.deleted_by = None
            self.deleted_at = None
            self.save()

    def natural_key(self):
        return self.username

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = "Custom User"
        verbose_name_plural = "Custom Users"


##========== MODEL and SOFT DELETE for CustomUser ===============


##========== MODEL FOR ROLE PERMISSIONS =========================
class RolePermission(models.Model):
    role = models.CharField(max_length=10, choices=CustomUser.ROLE_CHOICES)
    table_name = models.CharField(max_length=100)
    fields_allowed = models.JSONField(default=list)

    def __str__(self):
        return f"{self.role} - {self.table_name}"


##===============================================================


##========== MODEL FOR USER(ID) PERMISSIONS =====================
class UserPermission(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="user_permission"
    )
    fields_allowed = models.JSONField(default=list)
    table_name = models.CharField(max_length=100)

    def __str__(self):
        return f"User: {self.user.id}, Table: {self.table_name}"


auditlog.register(CustomUser)
