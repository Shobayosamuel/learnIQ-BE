from django.db import models
from user.models import CustomUser
from course.models import CourseModel
# Create your models here.

class Enrollment(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    is_enrolled = models.BooleanField(default=False)
    enrollment_date = models.DateField(auto_now_add=True)
    course = models.ForeignKey(CourseModel, on_delete=models.CASCADE)
    
    
    
    def __str__(self):
        return self.is_enrolled