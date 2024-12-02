from rest_framework.permissions import BasePermission
from accounts.models.accounts_model import UserPermission


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "admin"


class IsStaffUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "staff"


class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.user.role == "admin":
            return True
        return request.method in ["GET", "HEAD", "OPTION"]


class HasTablePermission(BasePermission):

    def has_permission(self, request, view):
        user = request.user

        if not user.is_authenticated:
            return False

        table_name = getattr(view, "table_name", None)
        if not table_name:
            return False

        user_permissions = UserPermission.objects.filter(
            user=user, table_name=table_name
        ).first()
        if user_permissions:
            return True
        return False
