import logging
from accounts.models.accounts_model import AuditLog
from django.utils.deprecation import MiddlewareMixin

class AuditLogMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if request.user.is_authenticated:
            AuditLog.objects.create(
                user=request.user,
                action=f'{request.method} {request.path}',
                ip_address=request.META.get('REMOTE_ADDR'),
                details=request.body.decode('utf-8') if request.body else ''
            )
        return response
