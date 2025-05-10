from django.urls import path

from . import views

urlpatterns=[
    path('',views.index,name='index'),
    path('dologin/',views.dologin,name='dologin'),
    path('doreg/',views.doreg,name='doreg'),
    path('uploadfiles/',views.uploadfiles,name='uploadfiles'),
    path('myfiles',views.myfiles,name='myfiles'),




    path('dulogin/',views.dulogin,name='dulogin'),
    path('dureg/',views.dureg,name='dureg'),
    path('viewdatausers/',views.viewdatausers,name='viewdatausers'),
    path('acceptdatauser/<id>',views.acceptdatauser,name='acceptdatauser'),
    path('viewfiles',views.viewfiles,name='viewfiles'),
    path('sendrequest/<int:id>',views.sendrequest,name='sendrequest'),
    path('viewresponse',views.viewresponse,name='viewresponse'),
    path("viewdatafile/<int:id>",views.viewdatafile,name='viewdatafile'),
    path('showfile',views.showfile,name='showfile'),
    path('viewdatafile',views.viewdatafile,name='viewdatafile'),
    path('mydatafile',views.mydatafile,name='mydatafile'),
]
