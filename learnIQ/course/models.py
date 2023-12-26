from django.db import models
from user.models import CustomUser

class CourseModel(models.Model):
    course_title = models.CharField(max_length=50)
    created_at = models.DateField(auto_now_add=True)
    length = models.IntegerField()
    instructor = models.CharField(max_length=50)
    description = models.TextField(max_length=150)
    price = models.IntegerField(default=10)
    no_of_students = models.IntegerField(default=0)
    
    def __str__(self):
        return self.course_title

