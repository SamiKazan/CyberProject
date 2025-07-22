from django.urls import path
from . import views

urlpatterns = [
    path('', views.index),
    path('register/', views.register),
    path('login/', views.login_view),
    path('logout/', views.logout_view),
    path('notes/', views.notes_home),
    path('notes/view/', views.note_detail),
    path('notes/search/', views.search_notes),
    path('notes/create/', views.create_note),
]
