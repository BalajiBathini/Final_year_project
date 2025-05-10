from django.db import models
import os

# Create your models here.
class DataOwner(models.Model):
    Name=models.CharField(max_length=100)
    Email=models.EmailField(max_length=70)
    password=models.CharField(max_length=50)
    contact = models.CharField(max_length=100)
    address = models.CharField(max_length=100)
    status=models.CharField(max_length=100,default='pending')


class DataUser(models.Model):
    Name=models.CharField(max_length=100)
    Email=models.EmailField(max_length=70)
    password=models.CharField(max_length=50)
    contact = models.CharField(max_length=100)
    address = models.CharField(max_length=100)
    status=models.CharField(max_length=100,default='pending')


class UploadFiles(models.Model):
    dataowner = models.CharField(max_length=100,default='pending')
    filename = models.CharField(max_length=50,default='empty')
    filedata = models.FileField(upload_to=os.path.join('static','files'))
    encrypted_data = models.CharField(max_length=500,default="empty")
    status = models.CharField(max_length=100,default='pending')