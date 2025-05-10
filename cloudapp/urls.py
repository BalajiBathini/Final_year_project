from django.urls import path

from . import views

urlpatterns=[
path('',views.index,name='index'),   
path('csplogin',views.csplogin,name='csplogin'),
path('userrequest',views.userrequest,name='userrequest'),
path('acceptrequest/<id>/',views.acceptrequest,name='acceptrequest'),
path('acptuserrequest/<id>',views.acptuserrequest,name='acptuserrequest'),
path('keygenerate',views.keygenerate,name='keygenerate'),
path('sendkey/<id>',views.sendkey,name='sendkey'),
path('viewowner',views.viewowner,name='viewowner'),
path('viewuser',views.viewuser,name='viewuser'),
]