from accounts.models.accounts_model import RolePermission, UserPermission
from django.core.exceptions import ObjectDoesNotExist


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


def get_dynamic_permission_byid(id, role, table_name):
    try:
        permission = UserPermission.objects.filter(
            user_id=id, table_name=table_name
        ).first()
        if permission:
            return permission.fields_allowed
        return get_dynamic_permission_fields(role, table_name)
    except ObjectDoesNotExist as e:
        raise PermissionError(str(e))
