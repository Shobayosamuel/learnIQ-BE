from django.urls import path

from . import views

urlpatterns = [
    path('<int:pk>/', views.CourseUdateDeleteRetrieve.as_view(), name='course-detail'),
    path("", views.CourseListCreate.as_view(), name="course-list-create"),

]
