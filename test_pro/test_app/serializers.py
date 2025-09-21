from rest_framework import serializers
from .models import PracAppUser

class UserSerializers(serializers.ModelSerializer):
    class Meta:
        model = PracAppUser
        fields = ["id", "name", "email", "mobile", "password", "profile_pic"]
        extra_kwargs = {
            "password": {"write_only": True}  # don't return password in responses
        }
