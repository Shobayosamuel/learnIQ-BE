# Generated by Django 4.2.5 on 2023-12-26 12:43

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("course", "0002_coursemodel_no_of_students_enrollment"),
    ]

    operations = [
        migrations.AlterField(
            model_name="coursemodel",
            name="no_of_students",
            field=models.IntegerField(default=0),
        ),
        migrations.DeleteModel(
            name="Enrollment",
        ),
    ]
