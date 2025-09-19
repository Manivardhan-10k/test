from django.urls import path
from . import views

urlpatterns = [
    path("", views.welcome),

    # Authentication
    path("register/", views.reg_user, name="register"),
    path("login/", views.login_user, name="login"),

    # CRUD
    path("users/", views.get_users, name="get_users"),
    path("users/<int:user_id>/", views.get_user, name="get_user"),
    path("users/<int:user_id>/update/", views.update_user, name="update_user"),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),
]
