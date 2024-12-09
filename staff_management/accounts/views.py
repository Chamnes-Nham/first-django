from rest_framework import generics, status
from rest_framework.response import Response
from .serializers import (
    UserSerializer,
    RefreshTokenSerializer,
    AuditLogSerializer,
    RolePermissionSerializer,
    CustomUserSerializer,
    UserPermissionSerializer,
)
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from accounts.permission import IsAdminUser, IsAdminOrReadOnly
from accounts.models.accounts_model import (
    CustomUser,
    AuditLog,
    UserPermission,
    RolePermission,
)
from rest_framework.throttling import UserRateThrottle
from django.db import IntegrityError
from drf_spectacular.utils import extend_schema, OpenApiExample
from drf_spectacular.utils import extend_schema_view, extend_schema
from .utils import get_dynamic_permission_fields, get_dynamic_permission_byid
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from rest_framework.decorators import action
from django.utils.timezone import now
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.apps import apps


class AuditLogListView(generics.ListAPIView):
    queryset = AuditLog.objects.all().order_by("-timestamp")
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser]


## register or create user
class UserSignupView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    @extend_schema(
        request=UserSerializer,
    )
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        email = request.data.get("email")
        job_title = request.data.get("job_title")
        department = request.data.get("department")
        contact_number = request.data.get("contact_number")
        address = request.data.get("address")
        role = request.data.get("role")

        if not username or not password:
            return Response(
                {"detail": "username and password are required."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        try:
            user = CustomUser(username=username)
            user.set_password(password)
            user.email = email
            user.job_title = job_title
            user.department = department
            user.contact_number = contact_number
            user.address = address
            user.role = role
            user.save()
            return Response(
                {"message": "User has created successfully."}, status=status.HTTP_200_OK
            )
        except IntegrityError:
            return Response(
                {"error": "User has already existing."},
                status=status.HTTP_400_BAD_REQUEST,
            )


## login user
class UserLoginView(APIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=UserSerializer,
        responses={200: None},
        examples=[
            OpenApiExample(
                "Login Example",
                description="Example of username and password input",
                value={"username": "exampleuser", "password": "password123"},
            ),
        ],
    )
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")
        # role = request.data.get("role")
        user = request.user
        if not username or not password:
            return Response(
                {"detail": "Username and Password are required!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = authenticate(username=username, password=password)
            if request.user.is_authenticated:
                logout(request)
                request.session.flush()
                request.session.cycle_key()

            login(request, user)
            return Response(
                {
                    "message": f"User: {user.username}, Role: {user.role} has ID: {user.id} Login Successfully."
                },
                status=status.HTTP_200_OK,
            )

        except CustomUser.DoesNotExist:
            return Response(
                {"detail": "User not found!"},
                status=status.HTTP_404_NOT_FOUND,
            )


def login_page(request):
    error = None

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if not username or not password:
            error = "Username and password are required."
            return render(request, "login.html", {"error": error})

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if request.user.is_authenticated:
                logout(request)
            login(request, user)
            session_id = request.session.session_key
            response = JsonResponse(
                {
                    "message": f"User: {user.username}, Role: {user.role}, ID: {user.id} login successfully"
                }
            )
            response.set_cookie("sessionid", session_id, secure=False, httponly=True)
            return response
        error = "Invalid username or password."

    return render(request, "login.html", {"error": error})


## Logout user
class LogoutAdminUser(APIView):
    permission_classes = [AllowAny]

    # serializer_class = UserSerializer
    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            logout(request)
            request.session.flush()
            request.session.cycle_key()

            response = Response({"message": "user logout successfully."})
            response.delete_cookie("sessionid", domain=settings.SESSION_COOKIE_DOMAIN)
            response.delete_cookie("csrf", domain=settings.CSRF_COOKIE_DOMAIN)

            return response
        response = Response({"message": "user logout successfully.."})
        response.delete_cookie("sessionid", domain=settings.SESSION_COOKIE_DOMAIN)
        response.delete_cookie("csrftoken", domain=settings.CSRF_COOKIE_DOMAIN)

        return response


@extend_schema_view(
    post=extend_schema(
        request=RefreshTokenSerializer, responses={200: "Logout successful"}
    )
)
class UserLogoutView(APIView):
    serializer_class = UserSerializer

    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if refresh_token is None:
                return Response({"detail": "resfresh token is require."})
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"detail": "Logout successfully."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response({"detail": str(e)}, status=400)


## dashboard for view number of role users
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    def get(self, request):
        count_admin = CustomUser.objects.filter(role="admin").count()
        count_staff = CustomUser.objects.filter(role="staff").count()

        return Response(
            {
                "admin_count": count_admin,
                "staff_count": count_staff,
            }
        )


## view all users
class AdminUserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]


## retrive, update, delete user by id
class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]


## update user role
class AdminUserRoleUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    def post(self, request, user_id):
        try:
            user = CustomUser.objects.get(id=user_id)
            new_role = request.data.get("role")
            if new_role in ["admin", "staff"]:
                user.role = new_role
                user.save()
                return Response(
                    {"detail": "Role has updated successfully."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Invalide role!!"}, status=status.HTTP_400_BAD_REQUEST
                )
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User Not Found!!!"}, status=status.HTTP_404_NOT_FOUND
            )


## view only current user
class UserProfile(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


## add permission for all users by role
class AddPermissionView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        template = render(request, "add_permission.html")
        return HttpResponse(template)

    def post(self, request):
        serializer = RolePermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            template = render(
                request,
                "add_permission.html",
                {"message": "permission has been added successfully."},
            )
            return HttpResponse(template)
        template = render(
            request,
            "add_permission.html",
            {"message": "Error: " + str(serializer.errors)},
        )
        return HttpResponse(template)

    def put(self, request):
        role = request.data.get("role")
        table_name = request.data.get("table_name")
        fields_allowed = request.data.get("fields_allowed")

        if not (role and table_name and fields_allowed):
            return Response(
                {"detail": "role, table_name and feilds_allowed are require."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            permission = RolePermission.objects.get(role=role)

            permission.role = role
            permission.table_name = table_name
            permission.fields_allowed = fields_allowed
            permission.save()

            return Response(
                {"detail": "Permission has updata successfully."},
                status=status.HTTP_200_OK,
            )

        except RolePermission.DoesNotExist:
            return Response({"error": "Permission does not exist cannot update."})


## access data(get) after permission
class GetDataView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]

    def get(self, request):
        print(f"Authenticated User: {request.user}")
        print(f"User Role: {getattr(request.user, 'role', None)}")
        user = request.user

        if user.role == "admin":
            queryset = CustomUser.objects.all()
            serializer = CustomUserSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        if not user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        role = getattr(request.user, "role", None)
        table_name = "customuser"
        allowed_fields = get_dynamic_permission_fields(role, table_name)

        if not allowed_fields:
            return Response(
                {"detail": f"No Permission for role '{role}' on Table '{table_name}'"},
                status=status.HTTP_403_FORBIDDEN,
            )

        queryset = CustomUser.objects.all()

        serializer = CustomUserSerializer(queryset, many=True, fields=allowed_fields)

        return Response(serializer.data, status=status.HTTP_200_OK)


class GetDataPermissionById(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role == "admin":
            queryset = CustomUser.objects.all()
            seriailizer = CustomUserSerializer(queryset, many=True)
            return Response(seriailizer.data, status=status.HTTP_200_OK)

        if not user.is_authenticated:
            return Response(
                {"message": "Authentication credential were not provide!!!"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        id = getattr(user, "id", None)
        table_name = "customuser"
        role = getattr(user, "role", None)
        allowed_fields = get_dynamic_permission_byid(id, role, table_name)

        if not allowed_fields:
            role = getattr(user, "role", None)
            table_name = "customuser"
            allowed_fields = get_dynamic_permission_fields(role, table_name)

            queryset = CustomUser.objects.all()
            seriailizer = CustomUserSerializer(
                queryset, many=True, fields=allowed_fields
            )
            return Response(seriailizer.data, status=200)
        queryset = CustomUser.objects.all()
        seriailizer = CustomUserSerializer(queryset, many=True, fields=allowed_fields)
        return Response(seriailizer.data, status=status.HTTP_200_OK)


## add, update, get, delete permission for specific users by id
class AdminPermissionView(APIView):
    permission_classes = [IsAuthenticated]

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        user_id = request.data.get("user_id")
        table_name = request.data.get("table_name")
        fields_allowed = request.data.get("fields_allowed")
        if not user_id or not table_name or not fields_allowed:
            return Response(
                {"error": "userid, tablename and fieldsallowed are require!!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response(
                {"error": "user not found!!"}, status=status.HTTP_404_NOT_FOUND
            )

        try:
            permission, created = UserPermission.objects.update_or_create(
                user=user,
                table_name=table_name,
                defaults={"fields_allowed": fields_allowed},
            )
        except Exception as e:
            return Response(
                {"error": f"Database error:  {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if created:
            return Response(
                {
                    "message": "Permission has added successfully.",
                    "data": fields_allowed,
                },
                status=status.HTTP_201_CREATED,
            )
        else:
            return Response(
                {
                    "message": "Permission has updated successfully.",
                    "data": fields_allowed,
                },
                status=status.HTTP_200_OK,
            )

    def get(self, request, *args, **kwargs):
        user = request.user
        id = user.id
        if user.role == "admin":
            queryset = UserPermission.objects.all()
            serializer = UserPermissionSerializer(queryset, many=True)
            return Response(serializer.data)
        else:
            queryset = UserPermission.objects.filter(user_id=id)
            serializer = UserPermissionSerializer(queryset, many=True)
            return Response(serializer.data)

    @action(detail=True, methods=["delete"])
    def delete(self, request, *args, **kwargs):
        user = request.user
        id = request.data.get("user_id")

        # if user.role != "admin":
        #     return Response({"message": "Only Admin user can delete permission!!"})
        queryset = UserPermission.objects.get(user_id=id)
        queryset.delete()
        return Response({"message": "Permission has delete successfully."})


class SoftDeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, user_id):
        try:
            user_delete = CustomUser.all_objects.get(id=user_id)
            user_delete.soft_delete(user=request.user)

            return Response(
                {"detail": f"User: {user_delete.username} soft-deleted successfully."},
                status=status.HTTP_200_OK,
            )
        except CustomUser.DoesNotExist:
            return Response(
                {"message": "User Not Fount."}, status=status.HTTP_404_NOT_FOUND
            )


class RestoreSoftDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        try:
            restore_user = CustomUser.all_objects.get(id=user_id)
            restore_user.restore()
            return Response(
                {"detail": f"User {restore_user.username} has restore successfully."},
                status=status.HTTP_200_OK,
            )
        except CustomUser.DoesNotExist:
            return Response(
                {"message": f"User Not Found."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserNotDelete(APIView):
    def get(self, request):
        queryset = CustomUser.not_deleted_objects.all()
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserDeleted(APIView):
    def get(self, request):
        queryset = CustomUser.all_objects.filter(deleted__isnull=False)
        serializer = UserSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CreateDefaultGroup(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        group_name = request.data.get("name")

        if not group_name:
            return Response(
                {"message": "group name is require!!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            group, create = Group.objects.get_or_create(name=group_name)

            if create:
                return Response(
                    {"detail": f"Group: {group_name} has created."},
                    status=status.HTTP_201_CREATED,
                )

            return Response(
                {"detail": f"Group: {group_name} has already existed."},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AddPermissonForGroup(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        group_name = request.data.get("name")
        table_name = request.data.get("table_name")
        fields = request.data.get("fields", [])

        if not group_name or not table_name or not fields:
            return Response(
                {"message": "group name, table name and fields allowed are require!!!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            group = Group.objects.get(name=group_name)
            content_type = ContentType.objects.get(model=table_name.lower())

            for field in fields:
                perm_codename = f"can_access_{table_name.lower()}_{field}"
                permission, created = Permission.objects.get_or_create(
                    codename=perm_codename,
                    defaults={
                        "name": f"can access fields: {field} of table name: {table_name}",
                        "content_type": content_type,
                    },
                )
                group.permissions.add(permission)

            return Response(
                {
                    "message": f"fields: {fields} of table: {table_name} has create successfully."
                },
                status=status.HTTP_201_CREATED,
            )

        except Group.DoesNotExist:
            return Response(
                {"error": f"Group: {group_name} doesn't exists!"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ContentType.DoesNotExist:
            return Response(
                {"error": f"Content_Type: {content_type} doesn't exist!"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response(
                {"error": f"Hello{str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetPermissionByGroup(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        accessible_data = {}

        user_groups = user.groups.all()
        if not user_groups:
            return Response({"error": "User is not assigned to any group."}, status=403)

        group_permissions = Permission.objects.filter(group__in=user_groups).distinct()

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

                    if table_name not in accessible_data:
                        accessible_data[table_name] = []

                    for obj in queryset:
                        obj_data = next(
                            (
                                item
                                for item in accessible_data[table_name]
                                if item["id"] == obj.id
                            ),
                            None,
                        )
                        if not obj_data:
                            obj_data = {"id": obj.id}
                            accessible_data[table_name].append(obj_data)

                        if hasattr(obj, field_name):
                            obj_data[field_name] = getattr(obj, field_name)

                except Exception as e:
                    print(f"Error processing permission {perm.codename}: {e}")
                    continue

        return Response({"accessible_data": accessible_data}, status=200)


class GetDataByPermission(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.is_superuser == True:
            queryset = CustomUser.objects.all()
            serializer = CustomUserSerializer(queryset, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        if not user.is_authenticated:
            return Response(
                {"message": "Authentication credential were not provided!!"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        id = getattr(user, "id", None)
        table_name = "customuser"
        role = getattr(user, "role", None)
        allowed_fields = get_dynamic_permission_byid(id, role, table_name)

        if not allowed_fields:
       
            accessible_data = {}
            user_groups = user.groups.all()
            if not user_groups:
                return Response(
                    {"message": f"User: {user_groups} doesn't exists in any groups."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            group_permissions = Permission.objects.filter(
                group__in=user_groups
            ).distinct()

            for perm in group_permissions:
                if perm.codename.startswith("can_access_"):
                    try:
                        codename_parts = perm.codename.split("_")
                        tables_name = codename_parts[2]
                        fields_name = "_".join(codename_parts[3:])

                        content_type = perm.content_type
                        model = apps.get_model(content_type.app_label, tables_name)
                        if not model:
                            continue

                        queryset = model.objects.all()

                        if tables_name not in accessible_data:
                            accessible_data[tables_name] = []

                        for obj in queryset:
                            obj_data = next(
                                (
                                    item
                                    for item in accessible_data[table_name]
                                    if item["id"] == obj.id
                                ),
                                None,
                            )
                        if not obj_data:
                            obj_data = {"id": obj.id}
                            accessible_data[table_name].append(obj_data)

                        if hasattr(obj, fields_name):
                            obj_data[fields_name] = getattr(obj, fields_name)

                    except Exception as e:
                        print(f"Error processing permission {perm.codename}: {e}")
                        continue

                    return Response({"accessible_data": accessible_data}, status=200)

        queryset = CustomUser.objects.all()
        serializer = CustomUserSerializer(queryset, many=True, fields=allowed_fields)

        return Response(serializer.data, status=status.HTTP_200_OK)
