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
    path('dashboard/', views.account, name='dashboard'),  # Redirects to account
    path('trade/', views.account, name='trade'),  # Legacy route - redirects to account
    
    # ==================== ACCOUNT MANAGEMENT ====================
    path('account/', views.account, name='account'),
    
    # ==================== INVESTMENT ROUTES ====================
    path('investments/', views.investments, name='investments'),
    path('investment/<int:token_id>/', views.investment_detail, name='investment_detail'),
    path('investment/<int:token_id>/buy/', views.buy_investment, name='buy_investment'),
    
    # ==================== DEPOSIT ROUTES ====================
    # These are the actual functional routes
    path('deposit/create/', views.create_deposit, name='create_deposit'),
    
    # ==================== WITHDRAWAL ROUTES ====================
    path('withdrawal/create/', views.create_withdrawal, name='create_withdrawal'),
    path('withdrawal/<int:withdrawal_id>/cancel/', views.cancel_withdrawal, name='cancel_withdrawal'),
    
    # ==================== ADMIN ROUTES ====================
    path('admin-panel/', views.myadmin, name='myadmin'),
    path('custom-admin/api/', views.admin_api, name='admin_api'),
    
    # ==================== WALLET MANAGEMENT ====================
    path('manage/fix-wallets/', views.fix_all_wallets, name='fix_all_wallets'),
    path('manage/debug-wallet/', views.debug_wallet, name='debug_wallet'),
    path('manage/debug-wallet/<int:user_id>/', views.debug_wallet, name='debug_wallet_user'),
    
    # ==================== ADMIN PAYOUT MANAGEMENT ====================
    path('manage/trigger-payout/', views.admin_trigger_payout, name='admin_trigger_payout'),
    path('manage/check-expired/', views.admin_check_expired, name='admin_check_expired'),
    path('manage/payout-stats/', views.admin_payout_stats, name='admin_payout_stats'),




    # ==================== EXPORT ROUTES (ADD THESE) ====================
path('export/deposits/', views.export_deposits_csv, name='export_deposits_csv'),
path('export/withdrawals/', views.export_withdrawals_csv, name='export_withdrawals_csv'),
path('export/investments/', views.export_investments_csv, name='export_investments_csv'),
path('export/tokens/', views.export_tokens_csv, name='export_tokens_csv'),
path('export/kyc/', views.export_kyc_csv, name='export_kyc_csv'),
path('export/logs/', views.export_logs_csv, name='export_logs_csv'),



    
    # ==================== ADMIN CATCH-UP PAYOUT ROUTES ====================
    path('manage/catch-up-payouts/', views.admin_catch_up_payouts, name='admin_catch_up_payouts'),
    path('manage/fix-investment/<int:investment_id>/', views.fix_investment_payouts, name='fix_investment_payouts'),
    
    # ==================== ADMIN INVESTMENT MANAGEMENT ====================
    path('manage/investment/<int:investment_id>/force-complete/', 
         views.admin_force_complete_investment, 
         name='admin_force_complete_investment'),
    path('manage/investment/<int:investment_id>/force-payout/', 
         views.admin_force_payout, 
         name='admin_force_payout'),
    
    # ==================== ADMIN USER MANAGEMENT ====================
    path('manage/user/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),
    
    # ==================== ADMIN SYSTEM MANAGEMENT ====================
    path('manage/system-status/', views.admin_system_status, name='admin_system_status'),
    
    # ==================== EXPORT ROUTES ====================
    path('export/transactions/', views.export_transactions_csv, name='export_transactions_csv'),
    path('export/users/', views.export_users_csv, name='export_users_csv'),
    
    # ==================== API ROUTES ====================
    path('api/wallet/balance/', views.api_wallet_balance, name='api_wallet_balance'),
    path('api/investment/stats/', views.api_investment_stats, name='api_investment_stats'),
    
    # ==================== SYSTEM ROUTES ====================
    path('health/', views.health_check, name='health_check'),
    path('initialize/', views.initialize_system, name='initialize_system'),
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