from django.db import models

# Create your models here.


class UserRequest(models.Model):
    Dataowner = models.CharField(max_length=100)
    Datauser = models.CharField(max_length=100)
    Filename =models.CharField(max_length=100)
    status = models.CharField(max_length=100)
    key = models.CharField(max_length=100,default='empty')
    mykey = models.CharField(max_length=100,default='empty')
