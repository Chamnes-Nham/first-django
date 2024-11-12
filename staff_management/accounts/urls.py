from django.urls import path
from accounts.views import (UserLoginView,
                             UserSignupView, 
                             UserLogoutView, 
                             UserProfile,
                             AdminDashboardView,
                             AdminUserListView,
                             AdminUserRoleUpdateView,
                             AdminUserDetailView,
                             AuditLogListView
                            )

urlpatterns = [
    path("signup/", UserSignupView.as_view(), name="user-signup"),
    path("login/", UserLoginView.as_view(), name="user-login"),
    path("logout/", UserLogoutView.as_view(), name="user-logout"),
    path("profile/", UserProfile.as_view(), name="user-profile"),
    path("api/admin/dashboard/", AdminDashboardView.as_view(), name="admin-dashboard"),
    path("api/admin/user/", AdminUserListView.as_view(), name="admin-listview"),
    path("api/admin/user/<int:pk>/", AdminUserDetailView.as_view(), name="admin-detail"),
    path("api/admin/user/<int:user_id>/role/", AdminUserRoleUpdateView.as_view(), name="udate-role"),
    path('audit-logs/', AuditLogListView.as_view(), name='audit-logs'),
]