from django.shortcuts import render,redirect

from .models import DataOwner,UploadFiles,DataUser
from cloudapp.models import UserRequest
from django.contrib import messages
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
key = get_random_bytes(16)


dataownerlogin='dologin.html'
dataownerreg = 'doreg.html'
dataownerhome = "dohome.html"
fileupload = "uploadfiles.html"
viewfile = "myfiles.html"
datauserlogin ="dulogin.html"
datauserreg = "dureg.html"
datuserhomepage ="duhome.html"
viewuserrequest = "userrequest.html"


# Create your views here.

# Data Owner Functions

def index(request):
    return render(request,'index.html')


def dologin(request):
    if request.method=="POST":
        Email=request.POST['email']
        password=request.POST['password']
        data= DataOwner.objects.filter(Email=Email,password=password).exists()
        print(data)
        if data ==True:
            request.session['doemail'] =Email
            return render(request,"dohome.html",{'email':Email})
        else:
            messages.warning(request,"Details doesn't exist's.")
            return render(request,dataownerlogin)
    return render(request,dataownerlogin)


def doreg(request):
    if request.method=="POST":
        Name=request.POST['name']
        Email=request.POST['email']
        password=request.POST['password1']
        conpasword=request.POST['password2']
        contact = request.POST['contact']
        address = request.POST['address']
        print(Name,Email,password,contact,address)
        if password == conpasword:
            data= DataOwner.objects.filter(Email=Email,password=password).exists()
            if data == False:
                data_insert =DataOwner(Name=Name,Email=Email,password=password,contact=contact,address=address)
                data_insert.save()
                return render(request,dataownerlogin)
            else:
                messages.warning(request,'Details already exists.')
                return render(request,dataownerreg)
        else:
            return render(request,dataownerreg)
    return render(request,dataownerreg)

def uploadfiles(request):
    global tag,nonce,ciphertext
    if request.method=="POST":
        file_data = request.FILES['filedata']
        file_name = file_data.name
        
        file_info = file_data.read()
        
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(file_info)
  
        nonce = cipher.nonce
        
        data = UploadFiles(filename=file_name,filedata=file_data,encrypted_data=ciphertext,dataowner=request.session['doemail'])
        data.save()
        request.session['tag'] = tag
        return render(request,fileupload,{"msg":"file uploaded succesfully"})
    return render(request,fileupload)

def myfiles(request):
    data =UploadFiles.objects.filter(dataowner=request.session['doemail'])
    return render(request,viewfile,{"data":data})



# Data User Functions

def dulogin(request):
    if request.method=="POST":
        Email=request.POST['duemail']
        password=request.POST['password']

        data= DataUser.objects.filter(Email=Email,password=password).exists()
        print(data)
        if data ==True:
            request.session['Email'] = Email
            return render(request,"duhome.html",{'email':Email})
        else:
            messages.warning(request,"Details doesn't exist's.")
            return render(request,datauserlogin)
    return render(request,datauserlogin)



def dureg(request):
    if request.method=="POST":
        Name=request.POST['name']
        Email=request.POST['duemail']
        password=request.POST['password1']
        conpasword=request.POST['password2']
        contact =request.POST['contact']
        address = request.POST['address']
        print(Name,Email,password,contact,address)
        if password == conpasword:
            data= DataUser.objects.filter(Email=Email,password=password).exists()
            if data == False:
                status='pending'
                data_insert =DataUser(Name=Name,Email=Email,password=password,contact=contact,address=address)
                data_insert.save()
                return render(request,datauserlogin)
            else:
                messages.warning(request,'Details already exists.')
                return render(request,datauserreg)
        else:
            return render(request,datauserreg)
    return render(request,datauserreg)


def viewdatausers(request):
    data =DataUser.objects.filter(last_name='pending')
    return render(request,'viewdatausers.html',{"datausers":data})


def acceptdatauser(request,id):
    data = DataUser.objects.get(id=id)
    # data.last_name='accepted'
    data.save()
    return redirect("viewdatausers")


def viewfiles(request):
    data = UploadFiles.objects.filter(status='pending')
    return render(request,'viewfiles.html',{'data':data})

def sendrequest(request,id):
    print(id)
    data = UploadFiles.objects.get(id=id)
    data.status='accepted'
    data.save()
    dataowner = data.dataowner
    filename = data.filename
    status = data.status
    key = tag
    print(tag)
    dc = UserRequest(Dataowner = dataowner,Datauser = request.session['Email'],Filename = filename ,status = status,key=key)
    dc.save()
    messages.add_message(request, messages.INFO, 'Request send to cloud')
    return redirect("viewfiles")



def viewresponse(request):
    dc = UserRequest.objects.filter(status='completed',Datauser=request.session['Email'])
    return render(request,'viewresponse.html',{'data':dc})

def viewdatafile(request,id):
    
    return render(request,"viewdatafile.html",{'id':id})


def mydatafile(request):
    if request.method=="POST":
        mykey = request.POST['key']
        data = UserRequest.objects.filter(mykey=mykey)
        print(data)
        newdata = [i.key for i in data]
        # data = newdata[0]
    
        if newdata !=[]:
            print(tag,nonce,ciphertext)
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)

            print(data)

            return render(request,'showfile.html',{'dc':data})
    else:
        messages.warning(request,'Enter the correct key')
        return render(request,'showfile.html',{'dc':data})
                                    


def showfile(request,id):
    print(id)
    dc = UserRequest.objects.filter(id=id)
    print(dc)
    print(tag)
    dc  = [i.key for i in dc]
    print(dc)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    print(data)

    return render(request,'showfile.html',{'dc':data})