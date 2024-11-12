from rest_framework import generics, status, views
from rest_framework.response import Response
from .serializers import UserSerializer, RefreshTokenSerializer, AuditLogSerializer
from rest_framework_simplejwt.tokens import RefreshToken 
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from accounts.permission import IsAdminUser
from accounts.models.accounts_model import CustomUser, AuditLog
from rest_framework.throttling import UserRateThrottle
from django.db import IntegrityError
from drf_spectacular.utils import extend_schema, OpenApiExample
from drf_spectacular.utils import extend_schema_view, extend_schema


# Create your views here.

class AuditLogListView(generics.ListAPIView):
    queryset = AuditLog.objects.all().order_by('-timestamp')
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdminUser]

class UserSignupView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

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


class UserLoginView(views.APIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request = UserSerializer,
        responses={200: None},
        examples=[
            OpenApiExample(
                "Login Example",
                description="Example of username and password input",
                value={"username": "exampleuser", "password": "password123"},
            ),
        ],
        )

    def post(self, request, *args, **kwags):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({"detail": "Username and Password are require!!"}, status = status.HTTP_400_BAD_REQUEST)
        
        try:
            user = CustomUser.objects.get(username=username)
            print(f"User found: {user.username}")
            if user.check_password(password):
                refresh = RefreshToken.for_user(user)
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                })
            else: 
                print("password does not match....")
                return Response({'detail': 'Invalid Credential!!'}, status=status.HTTP_401_UNAUTHORIZED)
        except CustomUser.DoesNotExist:
            return Response({"detail": "User not fount!!"}, status=status.HTTP_404_NOT_FOUND)
        
@extend_schema_view(
    post=extend_schema(
        request=RefreshTokenSerializer,  # Use the serializer you created
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
        
class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    def get(self, request):
        count_admin = CustomUser.objects.filter(role="admin").count()
        count_staff = CustomUser.objects.filter(role="staff").count()
        count_hr = CustomUser.objects.filter(role="hr").count()

        return Response({
            "admin_count": count_admin,
            "staff_count": count_staff,
            "hr_count": count_hr,
        })

class AdminUserListView(generics.ListAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

class AdminUserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

class AdminUserRoleUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = UserSerializer

    def post(self, request, user_id):
        try:
            user = CustomUser.objects.get(id = user_id)
            new_role = request.data.get("role")
            if new_role in ["admin", "staff", "hr"]:
                user.role = new_role
                user.save()
                return Response({"detail":"Role has updated successfully."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalide role!!"}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({"error": "User Not Found!!!"}, status=status.HTTP_404_NOT_FOUND)
    
class UserProfile(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user
