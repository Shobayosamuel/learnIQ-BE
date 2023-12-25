from django.shortcuts import render
from rest_framework import (
    generics
)
from .serializers import CourseSerializer
from .models import CourseModel
from rest_framework.permissions import IsAuthenticated, AllowAny
from drf_spectacular.utils import extend_schema, OpenApiResponse
# Create your views here.

@extend_schema(tags=["Course Detail, Delete, Update and Destroy"])
class CourseUdateDeleteRetrieve(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = [IsAuthenticated]
    queryset = CourseModel.objects.all()
    serializer_class = CourseSerializer

@extend_schema(tags=["List and create Course"])
class CourseListCreate(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    queryset = CourseModel.objects.all()
    serializer_class = CourseSerializer