from django.shortcuts import render
from django.http import HttpResponse

# Login views
def log(request):
    return render(request,'login.html')
# Register views
def reg(request):
    return render(request,'register.html')
# Dashboard views
def dash(request):
    return render(request,'dashboard.html')

