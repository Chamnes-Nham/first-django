import django_filters
from django.contrib.auth import get_user_model
from accounts.models.accounts_model import CustomUser
from rest_framework import filters
from django.contrib.auth.models import Permission
from django.apps import apps
from rest_framework.filters import BaseFilterBackend
from django.db.models import Q


class UserFilter(django_filters.FilterSet):
    username = django_filters.CharFilter(field_name="username", lookup_expr="icontains")
    role = django_filters.CharFilter(field_name="role", lookup_expr="icontains")
    id = django_filters.CharFilter(field_name='id')

    class Meta:
        model = CustomUser
        fields = ["username", "email", "id"]


class AccessibleDataFilterBackend(BaseFilterBackend):
    def filter_queryset(self, request, queryset, view):
        user = request.user
        user_groups = user.groups.all()
        if not user_groups:
            return queryset.none()

        group_permissions = Permission.objects.filter(group__in=user_groups).distinct()

        querysets = []
        for perm in group_permissions:
            if perm.codename.startswith("can_access_"):
                try:
                    codename_parts = perm.codename.split("_")
                    table_name = codename_parts[2]
                    field_name = "_".join(codename_parts[3:])

                    content_type = perm.content_type
                    model = apps.get_model(content_type.app_label, table_name)

                    if not model:
                        continue

                    queryset = model.objects.all()
                    querysets.append(queryset)

                except Exception as e:
                    print(f"Error processing permission {perm.codename}: {e}")
                    continue

        # Combine the querysets into a single queryset
        combined_queryset = None
        for queryset in querysets:
            if combined_queryset is None:
                combined_queryset = queryset
            else:
                combined_queryset = combined_queryset.union(queryset)

        return combined_queryset