from accounts.models.accounts_model import RolePermission, UserPermission
from django.core.exceptions import ObjectDoesNotExist
from django.apps import apps
from django.contrib.auth.models import Permission
from accounts.models.accounts_model import CustomUser
from django.db.models import Q
from django.apps import apps


def get_dynamic_permission_fields(role, table_name):
    try:
        permissions = RolePermission.objects.filter(
            role=role, table_name=table_name
        ).first()
        if not permissions:
            raise ObjectDoesNotExist(
                f"No RolePermission found for role '{role}' and table '{table_name}'."
            )
        return permissions.fields_allowed
    except ObjectDoesNotExist as e:
        raise PermissionError(str(e))


def get_dynamic_permission_byid(id, table_name):
    try:
        permission = UserPermission.objects.filter(
            user_id=id, table_name=table_name
        ).first()
        if permission:
            return permission.fields_allowed
    except ObjectDoesNotExist as e:
        raise PermissionError(str(e))


def get_accessible_data_by_group(user):

    user_groups = user.groups.all()
    if not user_groups.exists():
        return (
            CustomUser.objects.none(),
            [],
            {"error": "User is not assigned to any group."},
            False,
        )

    group_permissions = Permission.objects.filter(group__in=user_groups).distinct()
    accessible_user_ids = set()  # Store ID of accessible users
    fields = set()  # Store allowed fields

    for perm in group_permissions:
        if perm.codename.startswith("can_access_"):
            try:
                # Parse codename to extract table and field
                codename_parts = perm.codename.split("_")
                table_name = codename_parts[2]
                field_name = "_".join(codename_parts[3:])

                content_type = perm.content_type
                model = apps.get_model(content_type.app_label, table_name)

                if not model:
                    continue

                # Collect IDs of accessible users based on the permission
                user_ids = model.objects.values_list("id", flat=True)
                accessible_user_ids.update(user_ids)

                # Add the field to allowed fields
                fields.add(field_name)

            except Exception as e:
                print(f"Error processing permission {perm.codename}: {e}")
                continue

    # Return queryset and allowed fields
    if not accessible_user_ids:
        return (
            CustomUser.objects.none(),
            [],
            {"error": "No accessible users found for the user's group."},
            False,
        )
    
    # return CustomUser.objects.filter(id__in=accessible_user_ids), list(fields), {}, True
    return CustomUser.objects.filter(id__in=accessible_user_ids), list(fields), {}, True
