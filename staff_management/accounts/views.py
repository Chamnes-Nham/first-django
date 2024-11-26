from rest_framework import generics, status
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from .serializers import UserSerializer, RefreshTokenSerializer, AuditLogSerializer, RolePermissionSerializer, CustomUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken 
from rest_framework.views import APIView
from django.views import View
from rest_framework.permissions import AllowAny, IsAuthenticated
from accounts.permission import IsAdminUser, IsAdminOrReadOnly
from accounts.models.accounts_model import CustomUser, AuditLog, RolePermission
from rest_framework.throttling import UserRateThrottle
from django.db import IntegrityError
from drf_spectacular.utils import extend_schema, OpenApiExample
from drf_spectacular.utils import extend_schema_view, extend_schema
from .utils import get_dynamic_permission_fields
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.utils.decorators import method_decorator
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpResponse


class AuditLogListView(generics.ListAPIView):
    queryset = AuditLog.objects.all().order_by('-timestamp')
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
            return Response({"detail": "username and password are required."}, status=status.HTTP_401_UNAUTHORIZED)
        try:
            user = CustomUser(username = username)
            user.set_password(password)
            user.email = email
            user.job_title = job_title
            user.department = department
            user.contact_number = contact_number
            user.address = address
            user.role = role
            user.save()
            return Response({"message": "User has created successfully."}, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response({"error":"User has already existing."}, status=status.HTTP_400_BAD_REQUEST)

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

            if user.role == "admin":
                login(request, user)  
                return Response(
                    {
                        "message": "Admin login successful.",
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "role": user.role,
                        },
                        "session": request.session.session_key,
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                refresh = RefreshToken.for_user(user)
                return Response(
                    {
                        "message": "Login successful.",
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "role": user.role,
                        },
                        "token": {
                            "access_token": str(refresh.access_token),
                            "refresh_token": str(refresh),
                        },
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
            if user.role == "admin":
                if request.user.is_authenticated:
                    logout(request)  
                login(request, user)
                session_id = request.session.session_key

                response = JsonResponse({
                    "message": "Admin login successful.",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "role": user.role,
                    },
                })
                response.set_cookie("sessionid", session_id, httponly=True, secure=False)
                return response

            elif user.role == "staff":
                refresh = RefreshToken.for_user(user)
                return JsonResponse({
                    "message": "Staff login successful.",
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "role": user.role,
                    },
                    "token": {
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh),
                    },
                })

        # If authentication fails
        error = "Invalid username or password."

    return render(request, "login.html", {"error": error})

## Logout user        
@extend_schema_view(
    post=extend_schema(
        request=RefreshTokenSerializer, 
        responses={200: 'Logout successful'}
    )
)        
class UserLogoutView(APIView):
    serializer_class = UserSerializer
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token is None:
                return Response({"detail": "resfresh token is require."})
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'detail': 'Logout successfully.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'detail': str(e)}, status=400)

## dashboard for view number of role users        
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    def get(self, request):
        count_admin = CustomUser.objects.filter(role="admin").count()
        count_staff = CustomUser.objects.filter(role="staff").count()

        return Response({
            "admin_count": count_admin,
            "staff_count": count_staff,
        })

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
            user = CustomUser.objects.get(id = user_id)
            new_role = request.data.get("role")
            if new_role in ["admin", "staff"]:
                user.role = new_role
                user.save()
                return Response({"detail":"Role has updated successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalide role!!"}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"error": "User Not Found!!!"}, status=status.HTTP_404_NOT_FOUND)

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
        serializer = RolePermissionSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            template =  render(request, "add_permission.html", {"message": "permission has been added successfully."})
            return HttpResponse(template)
        template = render(request, "add_permission.html", {"message": "Error: " + str(serializer.errors) })
        return HttpResponse(template)
        #     return Response({'detail': 'Permission has added successfully.'}, status=status.HTTP_201_CREATED)
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

 ## access data(get) after permission   
class GetDataView(GenericAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsAdminOrReadOnly]

    def get(self, request):
        print(f"Authenticated User: {request.user}") 
        print(f"User Role: {getattr(request.user, 'role', None)}")  # Debug the role
        user = request.user

        if user.role == 'admin':
            queryset = CustomUser.objects.all()
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        if not user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        role = getattr(request.user, 'role', None)
        table_name = 'customuser'
        allowed_fields = get_dynamic_permission_fields(role, table_name)
        if not allowed_fields:
            return Response(
                {"detail": f"No Permission for role '{role}' on Table '{table_name}'.."}, status=status.HTTP_403_FORBIDDEN
            )
        queryset = CustomUser.objects.all()
        serializer = self.get_serializer(queryset, many=True, fields=allowed_fields)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
## add, update, get, delete permission for specific users by id
class AdminPermissionView(APIView):

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
     
        if not hasattr(request.user, 'role') or request.user.role != 'admin':
            return JsonResponse({"error": "Access denied. Admins only."}, status=status.HTTP_403_FORBIDDEN)

        staff_user_id = request.data.get('staff_user_id')
        if not staff_user_id:
            return Response({"error": "Staff user ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        data = request.data
        serializer = RolePermissionSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Permission created successfully.", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, *args, **kwargs):
       
        if not hasattr(request.user, 'role') or request.user.role != 'admin':
            return JsonResponse({"error": "Access denied. Admins only."}, status=status.HTTP_403_FORBIDDEN)

        staff_user_id = request.query_params.get('staff_user_id')
        if not staff_user_id:
            return Response({"error": "Staff user ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        permissions = RolePermission.objects.filter(user_id=staff_user_id)
        serializer = RolePermissionSerializer(permissions, many=True)
        return Response({"permissions": serializer.data}, status=status.HTTP_200_OK)

    def put(self, request, *args, **kwargs):
        
        if not hasattr(request.user, 'role') or request.user.role != 'admin':
            return JsonResponse({"error": "Access denied. Admins only."}, status=status.HTTP_403_FORBIDDEN)

        permission_id = request.data.get('id')
        if not permission_id:
            return Response({"error": "Permission ID is required for updates."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            permission = RolePermission.objects.get(id=permission_id)
        except RolePermission.DoesNotExist:
            return Response({"error": "Permission not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = RolePermissionSerializer(permission, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Permission updated successfully.", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        
        if not hasattr(request.user, 'role') or request.user.role != 'admin':
            return JsonResponse({"error": "Access denied. Admins only."}, status=status.HTTP_403_FORBIDDEN)

        permission_id = request.data.get('id')
        if not permission_id:
            return Response({"error": "Permission ID is required for deletion."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            permission = RolePermission.objects.get(id=permission_id)
            permission.delete()
            return Response({"message": "Permission deleted successfully."}, status=status.HTTP_200_OK)
        except RolePermission.DoesNotExist:
            return Response({"error": "Permission not found."}, status=status.HTTP_404_NOT_FOUND)
