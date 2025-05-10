from django.shortcuts import render,redirect
from django.contrib import messages
from userapp.models import DataOwner,UploadFiles,DataUser
from .models import UserRequest
from django.conf import settings
from django.core.mail import send_mail
import random

homepage = 'index.html'
cloudhomepage = 'cloudloghome.html'
cloudlogin = 'cslogin.html'
viewowners = 'viewowners.html'
viewusers = 'viewusers.html'

# Create your views here.

def index(request):
    return render(request,homepage)

def csplogin(request):
    if request.method=="POST":
        email = request.POST['email']
        password = request.POST['password']
        if email=='cloud@gmail.com' and password=="cloud":
            return render(request,cloudhomepage)
        messages.info(request,'invalid details')
        return render(request,cloudlogin)
    return render(request,cloudlogin)


def userrequest(request):
    data = UserRequest.objects.filter(status='accepted')
    return render(request,"userrequest.html",{'data':data})

def acceptrequest(request,id):
    print(id)
    dc =dc = UserRequest.objects.get(id=id)
    dc.status = 'updated'
    dc.save()
    return redirect("userrequest")

def keygenerate(request):
    da = UserRequest.objects.filter(status='updated')
    return render(request,"keygeneratater.html",{'data':da})

def sendkey(request,id):
    x = random.randint(000000,999999)
    print(x)
    dc = UserRequest.objects.get(id=id)
    dc.mykey = x
    dc.status = 'completed'
    dc.save()

    
    # m1 = "This message is automatic generated so dont reply to this Mail"
    # m2 = "Thanking you"
    # m3 = "Regards"
    # m4 = "Cloud."
    # con = "Your Request for the key {} is sended by the cloud server.".format(x)
    # Email =  request.session['Email']
    # subject = "FILE SHARING SYSTEM USING AES"
    # email_from = settings.EMAIL_HOST_USER
    # recipient_list = [Email]
    # text =  m1 + '\n' + con + '\n' + m2 + '\n' + m3 + '\n' + m4
    # send_mail(subject, text, email_from, recipient_list,fail_silently=False,)
    return redirect("keygenerate")  

def acptuserrequest(request,id):
    print(id)
    dc = UserRequest.objects.get(id=id)
    dc.status = 'updated'
    dc.save()
    return redirect("userrequest")

def viewowner(request):
    data =DataOwner.objects.all()
    return render(request,viewowners,{"data":data})

def viewuser(request):
    data =DataUser.objects.all()
    return render(request,viewusers,{"data":data})