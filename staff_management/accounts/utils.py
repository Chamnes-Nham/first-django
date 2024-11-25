from accounts.models.accounts_model import RolePermission
from django.core.exceptions import ObjectDoesNotExist

def get_dynamic_permission_fields(role, table_name):
    try:
        # Use the first matching record if multiple are found
        permission = RolePermission.objects.filter(role=role, table_name=table_name).first()
        if not permission:
            raise ObjectDoesNotExist(f"No RolePermission found for role '{role}' and table '{table_name}'.")
        return permission.fields_allowed
    except ObjectDoesNotExist as e:
        raise PermissionError(str(e))
