from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),

    path('vulnerabilities/', views.vuln_list, name='vuln_list'),
    path('vulnerabilities/new/', views.vuln_form, name='vuln_create'),
    path('vulnerabilities/<int:pk>/', views.vuln_detail, name='vuln_detail'),
    path('vulnerabilities/<int:pk>/edit/', views.vuln_form, name='vuln_edit'),
    path('vulnerabilities/<int:pk>/status/', views.vuln_status, name='vuln_status'),
    path('vulnerabilities/<int:pk>/assign/', views.vuln_assign, name='vuln_assign'),
    path('vulnerabilities/<int:pk>/delete/', views.vuln_delete, name='vuln_delete'),

    path('assets/', views.asset_list, name='asset_list'),
    path('assets/new/', views.asset_form, name='asset_create'),
    path('assets/<int:pk>/', views.asset_detail, name='asset_detail'),
    path('assets/<int:pk>/edit/', views.asset_form, name='asset_edit'),
    path('assets/<int:pk>/delete/', views.asset_delete, name='asset_delete'),

    path('import/', views.import_scan, name='import_scan'),
    path('import/template.csv', views.import_template, name='import_template'),

    path('reports/', views.reports, name='reports'),
    path('reports/export.csv', views.report_csv, name='report_csv'),

    path('history/', views.history, name='history'),

    path('categories/', views.category_list, name='category_list'),
    path('categories/new/', views.category_form, name='category_create'),
    path('categories/<int:pk>/edit/', views.category_form, name='category_edit'),
    path('categories/<int:pk>/delete/', views.category_delete, name='category_delete'),
]
