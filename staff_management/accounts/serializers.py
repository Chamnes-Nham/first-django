from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from accounts.models.accounts_model import CustomUser, RolePermission, UserPermission
from auditlog.models import LogEntry


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "id",
            "username",
            "email",
            "job_title",
            "department",
            "contact_number",
            "address",
            "role",
            "deleted_by",
            "deleted_at",
        ]
        extra_kwargs = {"password": {"write_only": True}}
        read_only_fields = ["role"]


class RolePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolePermission
        fields = "__all__"


class UserPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPermission
        fields = ["id", "user_id", "table_name", "fields_allowed"]

    def validate_fields_allowed(self, value):
        if not isinstance(value, list):
            raise serializers.ValueError("fields allowed must be a list!!!")
        return value


class CustomUserSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        fields = kwargs.pop("fields", None)
        super().__init__(*args, **kwargs)

        if fields:
            allowed = set(fields)
            existing = set(self.fields)
            for field_name in existing - allowed:
                self.fields.pop(field_name)

    class Meta:
        model = CustomUser
        fields = "__all__"


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogEntry
        fields = "__all__"


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
