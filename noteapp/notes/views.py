from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .models import Note
from django.db import connection
import logging
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger('notes')

def index(request):
    return render(request, 'index.html')

# A07 Insecure login (password saved as plaintext)
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        try:
            user = User.objects.get(username=username)
            if user.password == password:
                request.session['user_id'] = user.id
                return HttpResponse("Logged in")
        except User.DoesNotExist:
            pass
        # A09 No logging
        return HttpResponse("Login failed")
    return render(request, 'login.html')
''' 
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        if not username or not password:
            return HttpResponse("Username and password are required")
            
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            logger.info(f"User {username} logged in successfully")
            return redirect('/notes/')
        else:
            logger.warning(f"Login failed for user: {username}")
            return HttpResponse("Login failed - Invalid username or password")
    return render(request, 'login.html')
'''

def logout_view(request):
    logout(request)
    return redirect('/')

# A07 password saved as plaintext
def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = User.objects.create(username=username, password=password)
        login(request, user)
        return redirect('/notes/')
    return render(request, 'register.html')
# the create_user function automatically hashes the password
'''
def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = User.objects.create_user(username=username, password=password)
        login(request, user)
        return redirect('/notes/')
    return render(request, 'register.html')
'''

@login_required
def notes_home(request):
    notes = Note.objects.filter(owner=request.user)
    return render(request, 'notes.html', {'notes': notes})

# A01 Access control issue
def note_detail(request):
    note_id = request.GET.get("id")
    note = Note.objects.get(id=note_id)
    return HttpResponse(f"Note: {note.title} - {note.content}")
'''
@login_required
def note_detail(request):
    note_id = request.GET.get("id")
    note = get_object_or_404(Note, id=note_id, owner=request.user)
    return HttpResponse(f"Note: {note.title} - {note.content}")
'''

# A03 SQL injection
def search_notes(request):
    query = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT title FROM notes_note WHERE title LIKE '%{query}%'")
        results = cursor.fetchall()
    return HttpResponse(str(results))
''' 
@login_required
def search_notes(request):
    query = request.GET.get("q", "")
    if not query.strip():
        return HttpResponse("No search query given")
    
    query = query.replace('%', '\\%').replace('_', '\\_')
    search_param = "%" + query + "%"
    
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT title, content FROM notes_note WHERE title LIKE %s ESCAPE '\\' AND owner_id = %s", 
            [search_param, request.user.id]
        )
        results = cursor.fetchall()
    
    if results:
        return HttpResponse(str(results))
    else:
        return HttpResponse("No notes found")
'''

#no csrf token requirement
@csrf_exempt
@login_required
def create_note(request):
    if request.method == 'POST':
        title = request.POST['title']
        content = request.POST['content']
        Note.objects.create(title=title, content=content, owner=request.user)
        return redirect('/notes/')
    return render(request, 'create_note.html')
''' 
@login_required
def create_note(request):
    if request.method == 'POST':
        title = request.POST['title']
        content = request.POST['content']
        Note.objects.create(title=title, content=content, owner=request.user)
        return redirect('/notes/')
    return render(request, 'create_note.html')
'''