from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'
    
class IsStaffUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'staff'

class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.user.role == 'admin':
            return True
        return request.method in ['GET', 'HEAD', 'OPTION']
    