from pyexpat import model
from django.db import models

# Create your models here.
class Post(models.Model):
    text = models.CharField(max_length=240)