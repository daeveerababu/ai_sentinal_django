from django.shortcuts import render

def home_view(request):
    """
    View for the homepage of AI Sentinal
    """
    return render(request, 'home.html')

