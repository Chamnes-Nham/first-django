from rest_framework import serializers
from accounts.models.accounts_model import CustomUser, AuditLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'job_title', 'department', 'contact_number', 'address', 'role']
        extra_kwargs = {'password': {'write_only': True}}
        read_only_fields = ['role']
    

class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = '__all__'