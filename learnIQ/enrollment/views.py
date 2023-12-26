from django.shortcuts import get_object_or_404, render
from rest_framework import (
    generics,
    views
)
from .serializers import EnrollmentSerializer
from .models import CourseModel, Enrollment
from rest_framework.permissions import IsAuthenticated, AllowAny
from drf_spectacular.utils import extend_schema, OpenApiResponse
# Create your views here.

@extend_schema(tags=["Enrollment Detail, Delete, Update and Destroy"])
class EnrollmentView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = EnrollmentSerializer
    queryset = Enrollment.objects.all()
    permission_classes = [IsAuthenticated]
    
@extend_schema(tags=["Enrollment List and Create view"])
class EnrollmentListCreateView(generics.ListCreateAPIView):
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        course_id = self.request.data.get('course')  # Assuming the course ID is sent in the request data
        course = get_object_or_404(CourseModel, pk=course_id)
        serializer.save(user=self.request.user, course=course, is_enrolled=True)