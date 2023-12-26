from django.urls import path
from . import views

urlpatterns = [
    path("<int:pk>/", views.EnrollmentView.as_view(), name="enroll"),
    path("", views.EnrollmentListCreateView.as_view(), name="enroll-create")
]
