import bcrypt
import jwt
import datetime
import json

from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from .models import PracAppUser
from .serializers import UserSerializers

# JWT Config
JWT_SECRET = getattr(settings, "SECRET_KEY", "supersecret")
JWT_ALGO = "HS256"


# ----------------- JWT Helpers -----------------
def generate_jwt(user_id):
    """Generate JWT token for a user"""
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),  # expires in 2 hours
        "iat": datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return token


def verify_jwt(req):
    """Verify JWT token from Authorization header"""
    auth_header = req.headers.get("Authorization")
    if not auth_header:
        return None, JsonResponse({"error": "Missing Authorization header"}, status=401)

    try:
        token = auth_header.split(" ")[1]  # Expecting "Bearer <token>"
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload["user_id"], None
    except jwt.ExpiredSignatureError:
        return None, JsonResponse({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return None, JsonResponse({"error": "Invalid token"}, status=401)


# ----------------- Views -----------------
def welcome(req):
    return HttpResponse("Welcome to the Django app!")



@csrf_exempt
def reg_user(request):

    if request.method != "POST":
        return JsonResponse({"error": "Only POST method allowed"}, status=405)

    try:
        data = request.POST.copy()  # text fields from form-data
        profile_pic = request.FILES.get("profile_pic")  # file field

        # Validate password
        if not data.get("password"):
            return JsonResponse({"error": "Password is required"}, status=400)

        # Hash password
        hashed_pw = bcrypt.hashpw(
            data["password"].encode("utf-8"),
            bcrypt.gensalt()
        )
        data["password"] = hashed_pw.decode("utf-8")

        # Save user with serializer
        serializer = UserSerializers(data=data)
        if serializer.is_valid():
            user = serializer.save(profile_pic=profile_pic)  # save once

            # Cloudinary URL of uploaded image
            profile_url = user.profile_pic.url if user.profile_pic else None
            print("Uploaded image URL:", profile_url)

            return JsonResponse({
                "message": "User registered successfully",
                "profile_pic_url": profile_url
            }, status=201)

        else:
            return JsonResponse(serializer.errors, status=400)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)



@csrf_exempt
def login_user(req):
    """Login user and return JWT"""
    if req.method == "POST":
        try:
            data = json.loads(req.body.decode("utf-8"))
            email = data.get("email")
            password = data.get("password")

            if not email or not password:
                return JsonResponse({"error": "Email and password required"}, status=400)

            try:
                user = PracAppUser.objects.get(email=email)
            except PracAppUser.DoesNotExist:
                return JsonResponse({"error": "Invalid credentials"}, status=401)

            if bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
                token = generate_jwt(user.id)
                return JsonResponse({"message": "Login successful", "token": token}, status=200)
            else:
                return JsonResponse({"error": "Invalid credentials"}, status=401)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Only POST method allowed"}, status=405)


def get_users(req):
    """Get all users (requires JWT)"""
    user_id, error = verify_jwt(req)
    if error:
        return error

    if req.method == "GET":
        users = PracAppUser.objects.all()
        serializer = UserSerializers(users, many=True)
        return JsonResponse(serializer.data, safe=False, status=200)

    return JsonResponse({"error": "Only GET method allowed"}, status=405)


def get_user(req, user_id):
    """Get single user by ID (requires JWT)"""
    uid, error = verify_jwt(req)
    if error:
        return error

    if req.method == "GET":
        user = get_object_or_404(PracAppUser, id=user_id)
        serializer = UserSerializers(user)
        return JsonResponse(serializer.data, status=200)

    return JsonResponse({"error": "Only GET method allowed"}, status=405)


@csrf_exempt
def update_user(req, user_id):
    """Update user by ID (requires JWT)"""
    uid, error = verify_jwt(req)
    if error:
        return error

    if req.method == "PUT":
        try:
            user = get_object_or_404(PracAppUser, id=user_id)
            data = json.loads(req.body.decode("utf-8"))

            # Hash new password if provided
            if "password" in data:
                hashed_pw = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt())
                data["password"] = hashed_pw.decode("utf-8")

            serializer = UserSerializers(user, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return JsonResponse({"message": "User updated successfully", "data": serializer.data}, status=200)
            else:
                return JsonResponse({"errors": serializer.errors}, status=400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Only PUT method allowed"}, status=405)


@csrf_exempt
def delete_user(req, user_id):
    """Delete user by ID (requires JWT)"""
    uid, error = verify_jwt(req)
    if error:
        return error

    if req.method == "DELETE":
        try:
            user = get_object_or_404(PracAppUser, id=user_id)
            user.delete()
            return JsonResponse({"message": "User deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Only DELETE method allowed"}, status=405)
