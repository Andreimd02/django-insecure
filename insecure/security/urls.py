from django.urls import path
from django.contrib.auth.decorators import login_required
from . import views

urlpatterns = [
    # Secure user management
    path('users/<int:user_id>/', views.get_user, name='get_user'),
    
    # Protected admin area
    path('admin/', login_required(views.admin_index), name='admin_index'),
    
    # Secure search and logging
    path('search/', views.search, name='search'),
    path('log/', views.log, name='log'),
]
