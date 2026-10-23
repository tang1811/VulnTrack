from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    # หน้า Django admin สำหรับผู้พัฒนาเท่านั้น (ไม่แสดงในเมนู)
    path('dev-admin/', admin.site.urls),
    path('', include('accounts.urls')),
    path('', include('tracker.urls')),
]

handler403 = 'accounts.views.permission_denied'
