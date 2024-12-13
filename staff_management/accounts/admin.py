from django.contrib import admin
from accounts.models.accounts_model import CustomUser
from auditlog.models import LogEntry
from django.contrib.admin.sites import NotRegistered



try:
    admin.site.unregister(LogEntry)
except NotRegistered:
    pass  

class CustomLogEntryAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "actor", "action", "object_repr", "content_type")
    search_fields = ("actor__username", "object_repr")
    list_filter = ("action", "content_type")

admin.site.register(CustomUser)

