from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts.views import (
    UserLoginView,
    UserSignupView,
    UserLogoutView,
    UserProfile,
    AdminDashboardView,
    AdminUserListView,
    AdminUserRoleUpdateView,
    AdminUserDetailView,
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
    LogEntryAPIView,
    UserFilterView,
    TastViewSets,
)

# Define router and register routes
router = DefaultRouter()
router.register(r"tasks", TastViewSets, basename="task")

# Define urlpatterns
urlpatterns = [
    # User authentication routes
    path("signup/", UserSignupView.as_view(), name="user-signup"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("profile/", UserProfile.as_view(), name="user-profile"),

    # Admin-specific routes
    path("api/admin/dashboard/", AdminDashboardView.as_view(), name="admin-dashboard"),
    path("api/admin/users/", AdminUserListView.as_view(), name="admin-user-list"),
    path("api/admin/users/<int:pk>/", AdminUserDetailView.as_view(), name="admin-user-detail"),
    path("api/admin/users/<int:user_id>/role/", AdminUserRoleUpdateView.as_view(), name="admin-update-role"),

    # Permissions and groups
    path("permissions/add/", AddPermissionView.as_view(), name="add-permission"),
    path("permissions/get/", GetDataView.as_view(), name="get-permission-data"),
    path("permissions/admin/", AdminPermissionView.as_view(), name="admin-permission"),
    path("permissions/by-id/", GetDataPermissionById.as_view(), name="permission-by-id"),
    path("groups/create/", CreateDefaultGroup.as_view(), name="create-group"),
    path("groups/add-permission/", AddPermissonForGroup.as_view(), name="add-group-permission"),

    # User management
    path("users/soft-delete/<int:user_id>/", SoftDeleteUserView.as_view(), name="soft-delete-user"),
    path("users/restore/<int:user_id>/", RestoreSoftDeleteView.as_view(), name="restore-user"),
    path("users/not-deleted/", UserNotDelete.as_view(), name="not-deleted-users"),
    path("users/deleted-history/", UserDeleted.as_view(), name="deleted-users-history"),

    # Logs and filters
    path("logs/audit/", LogEntryAPIView.as_view(), name="audit-log"),
    path("users/filter/", UserFilterView.as_view({"get": "list"}), name="user-filter"),

    # Task management via DRF router
    path("", include(router.urls)),

    # Miscellaneous routes
    path("login-page/", login_page, name="login-page"),
    path("logout-admin/", LogoutAdminUser.as_view(), name="logout-admin"),
    path("api/permissions/data/", GetDataByPermission.as_view(), name="get-api-permissions"),
]
