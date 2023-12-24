from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.RegisterUserView.as_view(), name="register_user"),
	path("profile/", views.UserRetrieveUpdateDestroyView.as_view(), name="user_detail"),
	path("login/", views.UserLoginView.as_view(), name="login_user"),
	path("logout/", views.LogoutView.as_view(), name="logout_user"),
	path("reset_password/request/", views.PasswordTokenRequestView.as_view(), name="password_token_request"),
	path("reset_password/confirm/", views.PasswordTokenConfirmView.as_view(), name="password_token_confirm"),
	path("reset_password/", views.PasswordResetView.as_view(), name="password reset"),
]
