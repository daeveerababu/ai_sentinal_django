from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.views.static import serve
from .views import home_view
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
import yaml
import os

# Load the existing Swagger YAML file
swagger_yaml_path = os.path.join(settings.BASE_DIR, 'swagger.yaml')
with open(swagger_yaml_path, 'r') as f:
    swagger_content = yaml.safe_load(f)

# Create schema view using the loaded YAML
schema_view = get_schema_view(
    openapi.Info(
        title=swagger_content['info']['title'],
        default_version=swagger_content['info']['version'],
        description=swagger_content['info']['description'],
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('', home_view, name='home'),  # Homepage
    path('admin/', admin.site.urls),
    path('analyzer/', include('security_analyzer.urls')),
    
    # Swagger UI
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
