from django.urls import path
from accounts.views import (
    UserLoginView,
    UserSignupView,
    UserLogoutView,
    UserProfile,
    AdminDashboardView,
    AdminUserListView,
    AdminUserRoleUpdateView,
    AdminUserDetailView,
    AuditLogListView,
    AddPermissionView,
    GetDataView,
    AdminPermissionView,
    login_page,
    LogoutAdminUser,
    GetDataPermissionById,
    SoftDeleteUserView,
    RestoreSoftDeleteView,
    UserNotDelete,
    UserDeleted,
    CreateDefaultGroup,
    AddPermissonForGroup,
    GetPermissionByGroup,
    GetDataByPermission,
)

urlpatterns = [
    path("signup/", UserSignupView.as_view(), name="user-signup"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("profile/", UserProfile.as_view(), name="user-profile"),
    path("api/admin/dashboard/", AdminDashboardView.as_view(), name="admin-dashboard"),
    path("api/admin/user/", AdminUserListView.as_view(), name="admin-listview"),
    path(
        "api/admin/user/<int:pk>/", AdminUserDetailView.as_view(), name="admin-detail"
    ),
    path(
        "api/admin/user/<int:user_id>/role/",
        AdminUserRoleUpdateView.as_view(),
        name="udate-role",
    ),
    path("audit-logs/", AuditLogListView.as_view(), name="audit-logs"),
    path("addpermissions/", AddPermissionView.as_view(), name="add-permission "),
    path("getdata/", GetDataView.as_view(), name="get-data-permission"),
    path("admin-permission/", AdminPermissionView.as_view(), name="admin-permission"),
    path("login-page/", login_page, name="login-page"),
    path("logout-admin-user/", LogoutAdminUser.as_view(), name="logout-admin"),
    path("getdatabyid/", GetDataPermissionById.as_view(), name="getbyid"),
    path(
        "soft-delete/<int:user_id>/", SoftDeleteUserView.as_view(), name="soft-delete"
    ),
    path(
        "restore-softdelete/<int:user_id>/",
        RestoreSoftDeleteView.as_view(),
        name="soft-delete",
    ),
    path("data/", UserNotDelete.as_view(), name="user-not-delete"),
    path("delete-history/", UserDeleted.as_view(), name="history-delelted"),
    path("create_group/", CreateDefaultGroup.as_view(), name="create_group"),
    path("add_permission_group/", AddPermissonForGroup.as_view(), name="add-group-permissions"),
    path("get_data_group_permission/", GetPermissionByGroup.as_view(), name="get-data-group-permission"),
    path("get_api_user/", GetDataByPermission.as_view(), name="get-api"),
]
