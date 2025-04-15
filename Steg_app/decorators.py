from django.shortcuts import redirect
from functools import wraps

def login_required(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        # Check if the user is logged in
        if 'userid' not in request.session:
            # If not logged in, redirect to the login page
            return redirect('log')
        # If logged in, proceed to the requested view
        return function(request, *args, **kwargs)
    return wrap