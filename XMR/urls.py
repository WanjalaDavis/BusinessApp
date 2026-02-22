from django.urls import path
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from . import views

app_name = 'XMR'

urlpatterns = [
    # ==================== PUBLIC PAGES ====================
    path('', views.index, name='index'),
    path('about/', views.about, name='about'),
    
    # ==================== AUTHENTICATION ====================
    path('signup/', views.signupin, name='signupin'),
    path('signup-with-ref/', views.signup_with_ref, name='signup_with_ref'),
    path('login/', views.signupin, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # ==================== USER DASHBOARD ====================
    path('dashboard/', views.dashboard, name='dashboard'),
    path('trade/', views.dashboard, name='trade'),  # Legacy route
    
    # ==================== ACCOUNT MANAGEMENT ====================
    path('account/', views.account, name='account'),
    path('account/update/', views.update_profile, name='update_profile'),
    
    # ==================== INVESTMENT ROUTES ====================
    path('investments/', views.investments, name='investments'),
    path('investment/<int:token_id>/', views.investment_detail, name='investment_detail'),
    path('investment/<int:token_id>/buy/', views.buy_investment, name='buy_investment'),
    
    # ==================== DEPOSIT ROUTES ====================
    path('deposits/', views.deposits, name='deposits'),
    path('deposits/create/', views.create_deposit, name='create_deposit'),
    
    # ==================== WITHDRAWAL ROUTES ====================
    path('withdrawals/', views.withdrawals, name='withdrawals'),
    path('withdrawals/create/', views.create_withdrawal, name='create_withdrawal'),
    path('withdrawals/<int:withdrawal_id>/cancel/', views.cancel_withdrawal, name='cancel_withdrawal'),
    
    # ==================== REFERRAL ROUTES ====================
    path('referrals/', views.referrals, name='referrals'),
    path('referral/', views.referrals, name='referral'),  
    
    # ==================== TRANSACTION ROUTES ====================
    path('transactions/', views.transactions, name='transactions'),
    
    # ==================== ADMIN ROUTES (CONSOLIDATED) ====================
    path('admin-panel/', views.myadmin, name='myadmin'),
    path('custom-admin/api/', views.admin_api, name='admin_api'),
    
    # ==================== API ROUTES ====================
    path('api/wallet/balance/', views.api_wallet_balance, name='api_wallet_balance'),
    path('api/investment/stats/', views.api_investment_stats, name='api_investment_stats'),
]

# ==================== PASSWORD RESET ROUTES ====================
urlpatterns += [
    path('password-reset/', 
         auth_views.PasswordResetView.as_view(
             template_name='password_reset.html',
             email_template_name='password_reset_email.html',
             subject_template_name='password_reset_subject.txt'
         ),
         name='password_reset'),
    path('password-reset/done/',
         auth_views.PasswordResetDoneView.as_view(
             template_name='password_reset_done.html'
         ),
         name='password_reset_done'),
    path('password-reset/<uidb64>/<token>/',
         auth_views.PasswordResetConfirmView.as_view(
             template_name='password_reset_confirm.html'
         ),
         name='password_reset_confirm'),
    path('password-reset/complete/',
         auth_views.PasswordResetCompleteView.as_view(
             template_name='password_reset_complete.html'
         ),
         name='password_reset_complete'),
]

# ==================== SERVE MEDIA FILES IN DEVELOPMENT ====================
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)