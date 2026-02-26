from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models import Sum, Q
from django.db import transaction, IntegrityError
from django.http import HttpResponseRedirect, JsonResponse
from django.core.paginator import Paginator
from decimal import Decimal, InvalidOperation
import re
import json
import logging
import math
from datetime import timedelta

from .models import (
    UserProfile, Wallet, Transaction, MpesaPayment, 
    Token, Investment, WithdrawalRequest, SystemConfig, SystemLog
)

# Set up logging
logger = logging.getLogger(__name__)

# ==================== AUTO PAYOUT HELPER FUNCTION ====================

def check_user_payouts(user):
    """
    Enhanced version that catches up ALL missed payouts for a user
    Calculates how many 24-hour cycles have passed and issues all due payouts
    """
    if not user.is_authenticated:
        return 0
    
    from .models import Investment
    from django.utils import timezone
    
    # Get user's active investments that still have payouts remaining
    investments = Investment.objects.filter(
        user=user,
        status='ACTIVE',
        remaining_payouts__gt=0
    )
    
    processed_count = 0
    now = timezone.now()
    
    for investment in investments:
        try:
            # Calculate how many payouts should have been processed by now
            payouts_to_process = calculate_missed_payouts(investment, now)
            
            if payouts_to_process > 0:
                logger.info(f"Found {payouts_to_process} missed payouts for investment {investment.id}")
                
                # Process each missed payout
                for i in range(payouts_to_process):
                    success = investment.process_daily_payout()
                    if success:
                        processed_count += 1
                    else:
                        # Stop if we hit an error or investment completed
                        break
                        
        except Exception as e:
            logger.error(f"Auto-payout error for investment {investment.id}: {str(e)}")
    
    if processed_count > 0:
        logger.info(f"Processed {processed_count} catch-up payouts for user {user.username}")
    
    return processed_count


def calculate_missed_payouts(investment, current_time):
    """
    Calculate how many payouts are due for an investment based on 24-hour cycles
    Returns integer number of payouts that should have been processed
    """
    from datetime import timedelta
    
    # Don't calculate if investment is not active
    if investment.status != 'ACTIVE' or investment.remaining_payouts <= 0:
        return 0
    
    # Base reference time for calculations
    if not investment.last_payout_date:
        # No payouts yet - base is creation time
        reference_time = investment.created_at
        payouts_done = 0
    else:
        # Already had some payouts - base is last payout time
        reference_time = investment.last_payout_date
        # Count how many payouts have been done
        payouts_done = investment.token.return_days - investment.remaining_payouts
    
    # Calculate hours since reference time
    hours_since_ref = (current_time - reference_time).total_seconds() / 3600
    
    # Calculate how many 24-hour cycles have passed
    cycles_passed = math.floor(hours_since_ref / 24)
    
    # Calculate maximum possible payouts from start until now
    total_possible_payouts = math.floor(
        (current_time - investment.created_at).total_seconds() / (24 * 3600)
    )
    
    # Payouts that should have been done = total_possible - payouts_done
    expected_payouts = total_possible_payouts - payouts_done
    
    # Don't exceed remaining_payouts
    due_payouts = min(expected_payouts, investment.remaining_payouts)
    
    # Log for debugging
    if due_payouts > 0:
        logger.debug(f"""
            Investment {investment.id}:
            - Created: {investment.created_at}
            - Last payout: {investment.last_payout_date}
            - Current time: {current_time}
            - Hours since ref: {hours_since_ref}
            - Cycles passed: {cycles_passed}
            - Total possible: {total_possible_payouts}
            - Payouts done: {payouts_done}
            - Expected: {expected_payouts}
            - Due now: {due_payouts}
        """)
    
    return due_payouts


def catch_up_all_users_payouts():
    """
    Admin function to catch up payouts for ALL users
    Run this once to fix all historical payouts
    """
    from django.contrib.auth.models import User
    from django.db.models import Q
    
    total_processed = 0
    users_processed = 0
    
    # Get all users with active investments
    users_with_investments = User.objects.filter(
        investments__status='ACTIVE',
        investments__remaining_payouts__gt=0
    ).distinct()
    
    for user in users_with_investments:
        try:
            processed = check_user_payouts(user)
            if processed > 0:
                total_processed += processed
                users_processed += 1
                logger.info(f"Caught up {processed} payouts for user {user.username}")
        except Exception as e:
            logger.error(f"Error catching up payouts for user {user.username}: {str(e)}")
    
    logger.info(f"Complete catch-up finished: {total_processed} payouts for {users_processed} users")
    return total_processed, users_processed


# ==================== ADMIN VIEW FOR CATCH-UP ====================

@login_required(login_url='XMR:signupin')
def admin_catch_up_payouts(request):
    """Admin view to manually trigger catch-up for all users"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method == 'POST':
        total_processed, users_processed = catch_up_all_users_payouts()
        
        SystemLog.objects.create(
            log_type='ADMIN_ACTION',
            user=request.user,
            action='CATCH_UP_PAYOUTS',
            description=f'Admin triggered catch-up payouts: {total_processed} payouts for {users_processed} users'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Caught up {total_processed} payouts for {users_processed} users',
            'processed': total_processed,
            'users': users_processed
        })
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


# ==================== INDIVIDUAL INVESTMENT FIX ====================

def fix_investment_payouts(investment_id):
    """
    Fix payouts for a specific investment
    Useful for targeted fixes
    """
    from .models import Investment
    
    try:
        investment = Investment.objects.get(id=investment_id)
        user = investment.user
        
        processed = check_user_payouts(user)
        
        return {
            'success': True,
            'investment_id': investment_id,
            'user': user.username,
            'payouts_processed': processed,
            'new_remaining': investment.remaining_payouts,
            'new_status': investment.status
        }
    except Investment.DoesNotExist:
        return {'success': False, 'error': 'Investment not found'}
    except Exception as e:
        return {'success': False, 'error': str(e)}


# ==================== PUBLIC VIEWS ====================

def index(request):
    """Homepage view with system statistics"""
    # Get some stats for the homepage
    total_users = User.objects.count()
    active_investments = Investment.objects.filter(status='ACTIVE').count()
    total_paid = Transaction.objects.filter(
        transaction_type='PROFIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Get active tokens for display
    active_tokens = Token.objects.filter(status='ACTIVE')[:6]
    
    context = {
        'total_users': total_users,
        'active_investments': active_investments,
        'total_paid': total_paid,
        'active_tokens': active_tokens,
    }
    return render(request, 'index.html', context)


def about(request):
    """About page"""
    return render(request, 'about.html')


def signupin(request):
    """Combined signup and login view"""
    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect('XMR:myadmin')
        else:
            return redirect('XMR:account')
    
    # Check for referral code in URL
    if 'ref' in request.GET:
        referral_code = request.GET.get('ref')
        try:
            referrer = UserProfile.objects.get(referral_code=referral_code)
            request.session['referral_code'] = referral_code
            messages.info(request, f'You are being referred by {referrer.user.username}')
        except UserProfile.DoesNotExist:
            messages.warning(request, 'Invalid referral code')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        # ========== LOGIN HANDLER ==========
        if action == 'login':
            return handle_login(request)
        
        # ========== SIGNUP HANDLER ==========
        elif action == 'signup':
            return handle_signup(request)
    
    return render(request, 'signupin.html')


def handle_login(request):
    """Handle user login"""
    username = request.POST.get('login_username')
    password = request.POST.get('login_password')
    
    # Basic validation
    if not username or not password:
        messages.error(request, 'Both username and password are required.')
        return render(request, 'signupin.html')
    
    # Authenticate user
    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        # Check if user is banned
        try:
            if user.profile.is_banned:
                messages.error(request, f'Your account has been banned. Reason: {user.profile.ban_reason or "No reason provided"}')
                return render(request, 'signupin.html')
        except UserProfile.DoesNotExist:
            pass
        
        login(request, user)
        
        # Log the login
        SystemLog.objects.create(
            log_type='INFO',
            user=user,
            action='USER_LOGIN',
            description=f'User logged in from IP: {get_client_ip(request)}',
            ip_address=get_client_ip(request)
        )
        
        # Redirect based on admin status
        if user.is_staff:
            messages.success(request, 'Welcome back, Admin!')
            return redirect('XMR:myadmin')
        else:
            messages.success(request, f'Welcome back, {user.first_name or user.username}!')
            return redirect('XMR:account')
    else:
        messages.error(request, 'Invalid username or password.')
        return render(request, 'signupin.html')


def handle_signup(request):
    """Handle user registration"""
    username = request.POST.get('username')
    full_name = request.POST.get('full_name')
    email = request.POST.get('email')
    phone = request.POST.get('phone')
    password1 = request.POST.get('password1')
    password2 = request.POST.get('password2')
    referral_code = request.POST.get('referral_code', '').strip()
    
    # Validate all fields are present
    if not all([username, full_name, email, phone, password1, password2]):
        messages.error(request, 'All fields are required.')
        return render(request, 'signupin.html')
    
    # Password match validation
    if password1 != password2:
        messages.error(request, 'Passwords do not match.')
        return render(request, 'signupin.html')
    
    # Password strength
    if len(password1) < 8:
        messages.error(request, 'Password must be at least 8 characters long.')
        return render(request, 'signupin.html')
    
    # Add password complexity check
    if not re.search(r'[A-Z]', password1):
        messages.error(request, 'Password must contain at least one uppercase letter.')
        return render(request, 'signupin.html')
    
    if not re.search(r'[0-9]', password1):
        messages.error(request, 'Password must contain at least one number.')
        return render(request, 'signupin.html')
    
    # Username validation
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        messages.error(request, 'Username must be 3-20 characters and can only contain letters, numbers, and underscores.')
        return render(request, 'signupin.html')
    
    # Email validation
    try:
        validate_email(email)
    except ValidationError:
        messages.error(request, 'Please enter a valid email address.')
        return render(request, 'signupin.html')
    
    # Phone validation (Kenyan format)
    phone = clean_phone_number(phone)
    if not validate_phone_number(phone):
        messages.error(request, 'Please enter a valid Kenyan phone number (e.g., 0712345678 or 254712345678)')
        return render(request, 'signupin.html')
    
    # Check if username already exists
    if User.objects.filter(username=username).exists():
        messages.error(request, 'Username already taken. Please choose another.')
        return render(request, 'signupin.html')
    
    # Check if email already exists
    if User.objects.filter(email=email).exists():
        messages.error(request, 'Email already registered. Please use login or another email.')
        return render(request, 'signupin.html')
    
    # Check if phone already exists
    if UserProfile.objects.filter(phone_number=phone).exists():
        messages.error(request, 'Phone number already registered. Please use login or another number.')
        return render(request, 'signupin.html')
    
    # Validate referral code if provided
    referrer_profile = None
    if referral_code:
        try:
            referrer_profile = UserProfile.objects.get(referral_code=referral_code)
        except UserProfile.DoesNotExist:
            messages.error(request, 'Invalid referral code. Please check and try again.')
            return render(request, 'signupin.html')
    
    # Create user with transaction to ensure data integrity
    try:
        with transaction.atomic():
            # Split full name
            name_parts = full_name.strip().split(' ', 1)
            first_name = name_parts[0]
            last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password1,
                first_name=first_name,
                last_name=last_name
            )
            
            # Get or create profile (signals should create it, but just in case)
            profile, created = UserProfile.objects.get_or_create(user=user)
            
            # Update profile with registration data
            profile.phone_number = phone
            profile.national_id_name = full_name
            if referrer_profile:
                profile.referred_by = referrer_profile
            profile.save()
            
            # Ensure wallet exists
            wallet, created = Wallet.objects.get_or_create(user=user)
            
            # Log registration
            SystemLog.objects.create(
                log_type='INFO',
                user=user,
                action='USER_REGISTERED',
                description=f'New user registered with referral: {referral_code or "None"}',
                ip_address=get_client_ip(request)
            )
            
            # Clear session referral code
            if 'referral_code' in request.session:
                del request.session['referral_code']
            
            # Auto-login
            authenticated_user = authenticate(request, username=username, password=password1)
            if authenticated_user:
                login(request, authenticated_user)
                
                if referrer_profile:
                    messages.success(request, f'Account created successfully! You were referred by {referrer_profile.user.username}.')
                else:
                    messages.success(request, 'Account created successfully!')
                
                return redirect('XMR:account')
            else:
                messages.success(request, 'Account created. Please log in.')
                return render(request, 'signupin.html')
    
    except Exception as e:
        messages.error(request, f'Error creating account: {str(e)}')
        logger.error(f"Signup error: {str(e)}", exc_info=True)
        return render(request, 'signupin.html')


def logout_view(request):
    """Handle user logout"""
    if request.user.is_authenticated:
        SystemLog.objects.create(
            log_type='INFO',
            user=request.user,
            action='USER_LOGOUT',
            description='User logged out',
            ip_address=get_client_ip(request)
        )
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('XMR:signupin')


def signup_with_ref(request):
    """Handle signup with referral code in URL"""
    referral_code = request.GET.get('ref')
    if referral_code:
        try:
            referrer = UserProfile.objects.get(referral_code=referral_code)
            request.session['referral_code'] = referral_code
            messages.info(request, f'You are being referred by {referrer.user.username}')
        except UserProfile.DoesNotExist:
            messages.warning(request, 'Invalid referral code')
    return redirect('XMR:signupin')


# ==================== USER ACCOUNT VIEW ====================

@login_required(login_url='XMR:signupin')
def account(request):
    """Consolidated user account dashboard with all features"""
    
    # ===== AUTO PAYOUT CHECK =====
    # Check and process any due payouts when user visits their account
    check_user_payouts(request.user)
    # =============================
    
    try:
        profile = request.user.profile
        wallet = request.user.wallet
    except UserProfile.DoesNotExist:
        profile = UserProfile.objects.create(
            user=request.user,
            phone_number="",
            national_id_name=request.user.get_full_name() or request.user.username
        )
        wallet = Wallet.objects.create(user=request.user)
    except Wallet.DoesNotExist:
        wallet = Wallet.objects.create(user=request.user)
    
    # Get user's deposits
    deposits = MpesaPayment.objects.filter(
        user=request.user
    ).order_by('-created_at')[:20]
    
    # Get user's withdrawals
    withdrawals = WithdrawalRequest.objects.filter(
        user=request.user
    ).order_by('-created_at')[:20]
    
    # Get user's transactions
    transactions = Transaction.objects.filter(
        wallet=wallet
    ).select_related('investment', 'withdrawal').order_by('-created_at')[:30]
    
    # Get user's active investments (status = ACTIVE)
    active_investments = Investment.objects.filter(
        user=request.user,
        status='ACTIVE'
    ).select_related('token').order_by('-created_at')
    
    # Get user's completed investments (for history)
    completed_investments = Investment.objects.filter(
        user=request.user,
        status='COMPLETED'
    ).select_related('token').order_by('-created_at')[:20]
    
    # Get all investments (including both active and completed)
    all_investments = Investment.objects.filter(
        user=request.user
    ).select_related('token').order_by('-created_at')[:50]
    
    # Get pending counts
    pending_deposits = MpesaPayment.objects.filter(
        user=request.user,
        status='PENDING'
    ).count()
    
    pending_withdrawals = WithdrawalRequest.objects.filter(
        user=request.user,
        status='PENDING'
    ).count()
    
    # Calculate dashboard stats
    total_invested = active_investments.aggregate(total=Sum('amount'))['total'] or 0
    total_earned = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='PROFIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Get next payout (soonest ending investment)
    next_payout = active_investments.order_by('end_date').first()
    
    # Calculate next payout days left
    if next_payout:
        days_left = (next_payout.end_date - timezone.now()).days
        if days_left < 0:
            days_left = 0
    else:
        days_left = 0
    
    # Get referral data
    referrals = UserProfile.objects.filter(
        referred_by=profile
    ).select_related('user').order_by('-created_at')
    
    referral_data = []
    total_referral_earnings = Decimal('0')
    
    for ref in referrals:
        # Get first deposit
        first_deposit = Transaction.objects.filter(
            wallet=ref.user.wallet,
            transaction_type='DEPOSIT',
            status='COMPLETED'
        ).order_by('created_at').first()
        
        first_deposit_amount = first_deposit.amount if first_deposit else 0
        
        # Get bonus earned from this referral
        bonus = Transaction.objects.filter(
            wallet=wallet,
            transaction_type='REFERRAL_BONUS',
            description__icontains=ref.user.username
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        total_referral_earnings += bonus
        
        referral_data.append({
            'user': ref.user,
            'created_at': ref.created_at,
            'first_deposit': first_deposit_amount,
            'bonus_earned': bonus,
            'is_active': ref.user.last_login and 
                        ref.user.last_login > timezone.now() - timedelta(days=30)
        })
    
    # Get payment instructions from system config
    paybill = SystemConfig.get_config('mpesa_paybill', '123456')
    account_no = SystemConfig.get_config('mpesa_account', request.user.username)
    min_deposit = SystemConfig.get_config('min_deposit', 800)
    min_withdrawal = SystemConfig.get_config('min_withdrawal', 200)
    
    # Current date for greeting
    current_date = timezone.now()
    
    # Get greeting based on time
    hour = timezone.now().hour
    if hour < 12:
        greeting = "Morning"
    elif hour < 17:
        greeting = "Afternoon"
    else:
        greeting = "Evening"
    
    context = {
        # User and profile
        'user': request.user,
        'profile': profile,
        'wallet': wallet,
        'available_balance': wallet.available_balance(),
        'locked_balance': wallet.locked_balance,
        'total_balance': wallet.balance + wallet.locked_balance,
        
        # Stats
        'total_invested': total_invested,
        'total_earned': total_earned,
        'total_referral_earnings': total_referral_earnings,
        'total_referrals': referrals.count(),
        'active_referrals': sum(1 for r in referral_data if r['is_active']),
        
        # Pending counts
        'pending_deposits': pending_deposits,
        'pending_withdrawals': pending_withdrawals,
        
        # Lists
        'deposits': deposits,
        'withdrawals': withdrawals,
        'transactions': transactions,
        'active_investments': active_investments,
        'completed_investments': completed_investments,
        'all_investments': all_investments,
        'referrals': referral_data,
        
        # Next payout
        'next_payout': next_payout,
        'days_left': days_left,
        
        # Payment configs
        'paybill': paybill,
        'account_no': account_no,
        'min_deposit': min_deposit,
        'min_withdrawal': min_withdrawal,
        
        # Verification status
        'phone_verified': profile.phone_verified,
        'id_verified': profile.id_verified,
        
        # Current date and greeting
        'current_date': current_date,
        'greeting': greeting,
    }
    
    # Handle POST requests for profile updates, password changes, KYC uploads
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'update_profile':
            return handle_profile_update(request, profile)
        elif action == 'change_password':
            return handle_password_change(request)
        elif action == 'upload_kyc':
            return handle_kyc_upload(request, profile)
    
    return render(request, 'account.html', context)


def handle_profile_update(request, profile):
    """Handle profile update"""
    phone = request.POST.get('phone')
    national_id_name = request.POST.get('national_id_name')
    
    if phone:
        # Validate phone
        phone = clean_phone_number(phone)
        if not validate_phone_number(phone):
            messages.error(request, 'Please enter a valid Kenyan phone number')
            return redirect('XMR:account')
        
        # Check if phone is already taken
        if UserProfile.objects.exclude(pk=profile.pk).filter(phone_number=phone).exists():
            messages.error(request, 'Phone number already in use by another account')
            return redirect('XMR:account')
        
        profile.phone_number = phone
    
    if national_id_name:
        profile.national_id_name = national_id_name
    
    profile.save()
    messages.success(request, 'Profile updated successfully!')
    return redirect('XMR:account')


def handle_password_change(request):
    """Handle password change"""
    current_password = request.POST.get('current_password')
    new_password1 = request.POST.get('new_password1')
    new_password2 = request.POST.get('new_password2')
    
    if not request.user.check_password(current_password):
        messages.error(request, 'Current password is incorrect')
        return redirect('XMR:account')
    
    if new_password1 != new_password2:
        messages.error(request, 'New passwords do not match')
        return redirect('XMR:account')
    
    if len(new_password1) < 8:
        messages.error(request, 'Password must be at least 8 characters long')
        return redirect('XMR:account')
    
    request.user.set_password(new_password1)
    request.user.save()
    
    # Re-authenticate user
    user = authenticate(username=request.user.username, password=new_password1)
    login(request, user)
    
    messages.success(request, 'Password changed successfully!')
    return redirect('XMR:account')


def handle_kyc_upload(request, profile):
    """Handle KYC document upload"""
    id_front = request.FILES.get('id_front')
    id_back = request.FILES.get('id_back')
    selfie = request.FILES.get('selfie')
    
    if id_front:
        profile.id_front_image = id_front
    if id_back:
        profile.id_back_image = id_back
    if selfie:
        profile.selfie_with_id = selfie
    
    profile.save()
    messages.success(request, 'KYC documents uploaded successfully! They will be verified by admin.')
    return redirect('XMR:account')


# ==================== DEPOSIT VIEWS ====================

@login_required(login_url='XMR:signupin')
def create_deposit(request):
    """Create a new deposit request"""
    if request.method != 'POST':
        return redirect('XMR:account')
    
    amount = request.POST.get('amount')
    phone_number = request.POST.get('phone_number')
    mpesa_message = request.POST.get('mpesa_message')
    mpesa_screenshot = request.FILES.get('mpesa_screenshot')
    
    # Validate amount
    try:
        amount = Decimal(amount)
        min_deposit = SystemConfig.get_config('min_deposit', 800)
        if amount < min_deposit:
            messages.error(request, f'Minimum deposit is {min_deposit} KSH')
            return redirect('XMR:account')
    except (TypeError, ValueError, InvalidOperation):
        messages.error(request, 'Invalid amount')
        return redirect('XMR:account')
    
    # Validate phone
    phone_number = clean_phone_number(phone_number)
    if not validate_phone_number(phone_number):
        messages.error(request, 'Please enter a valid Kenyan phone number')
        return redirect('XMR:account')
    
    # Check if message or screenshot is provided
    if not mpesa_message and not mpesa_screenshot:
        messages.error(request, 'Please provide either the M-Pesa message or screenshot')
        return redirect('XMR:account')
    
    try:
        # Create M-Pesa payment record
        payment = MpesaPayment.objects.create(
            user=request.user,
            amount=amount,
            phone_number=phone_number,
            mpesa_message=mpesa_message or '',
            mpesa_screenshot=mpesa_screenshot
        )
        
        # Try to extract data from message if provided
        if mpesa_message:
            payment.extract_mpesa_data()
        
        messages.success(request, 'Deposit request submitted successfully! It will be verified by admin.')
        
        # Log the deposit request
        SystemLog.objects.create(
            log_type='INFO',
            user=request.user,
            action='DEPOSIT_CREATED',
            description=f'Deposit request for {amount} KSH created'
        )
        
    except Exception as e:
        messages.error(request, f'Error creating deposit: {str(e)}')
        logger.error(f"Deposit creation error: {str(e)}", exc_info=True)
    
    return HttpResponseRedirect('/account/?tab=deposits')


# ==================== WITHDRAWAL VIEWS ====================

@login_required(login_url='XMR:signupin')
def create_withdrawal(request):
    """Create a new withdrawal request - ONLY affects available balance"""
    if request.method != 'POST':
        return redirect('XMR:account')
    
    amount = request.POST.get('amount')
    payment_method = request.POST.get('payment_method', 'MPESA')
    phone_number = request.POST.get('phone_number', '').strip()
    bank_details = request.POST.get('bank_details', '').strip()
    
    wallet = request.user.wallet
    
    # Validate amount
    try:
        amount = Decimal(amount)
        min_withdrawal = SystemConfig.get_config('min_withdrawal', 200)
        
        if amount < min_withdrawal:
            messages.error(request, f'Minimum withdrawal is {min_withdrawal} KSH')
            return redirect('XMR:account')
        
        # CHECK AVAILABLE BALANCE ONLY (balance field)
        if wallet.balance < amount:
            messages.error(
                request, 
                f'Insufficient available balance. You have {wallet.balance} KSH available, but requested {amount} KSH.'
            )
            return redirect('XMR:account')
            
    except (TypeError, ValueError, InvalidOperation):
        messages.error(request, 'Invalid amount')
        return redirect('XMR:account')
    
    # Validate based on payment method
    if payment_method == 'MPESA':
        phone_number = clean_phone_number(phone_number)
        if not validate_phone_number(phone_number):
            messages.error(request, 'Please enter a valid Kenyan phone number for M-Pesa withdrawal')
            return redirect('XMR:account')
    elif payment_method == 'BANK':
        if not bank_details:
            messages.error(request, 'Please provide bank account details')
            return redirect('XMR:account')
    
    try:
        # Create withdrawal request
        withdrawal = WithdrawalRequest.objects.create(
            user=request.user,
            amount=amount,
            payment_method=payment_method,
            phone_number=phone_number if payment_method == 'MPESA' else None,
            bank_details=bank_details if payment_method == 'BANK' else None
        )
        
        # NOTE: WithdrawalRequest.save() no longer locks the amount
        # It just checks available balance but doesn't modify it
        
        messages.success(request, f'Withdrawal request for {amount} KSH submitted successfully! It will be processed by admin.')
        
        # Log the withdrawal request
        SystemLog.objects.create(
            log_type='INFO',
            user=request.user,
            action='WITHDRAWAL_CREATED',
            description=f'Withdrawal request for {amount} KSH created'
        )
        
    except ValidationError as e:
        messages.error(request, str(e))
    except Exception as e:
        messages.error(request, f'Error creating withdrawal: {str(e)}')
        logger.error(f"Withdrawal creation error: {str(e)}", exc_info=True)
    
    return HttpResponseRedirect('/account/?tab=withdrawals')


@login_required(login_url='XMR:signupin')
def cancel_withdrawal(request, withdrawal_id):
    """Cancel a pending withdrawal request - NO FUNDS TO UNLOCK"""
    withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id, user=request.user)
    
    if withdrawal.status != 'PENDING':
        messages.error(request, 'Can only cancel pending withdrawals')
        return redirect('XMR:account')
    
    try:
        withdrawal.cancel()  # No funds to unlock
        messages.success(request, 'Withdrawal request cancelled successfully')
        
        SystemLog.objects.create(
            log_type='INFO',
            user=request.user,
            action='WITHDRAWAL_CANCELLED',
            description=f'Withdrawal {withdrawal.request_id} cancelled'
        )
        
    except ValidationError as e:
        messages.error(request, str(e))
    
    return HttpResponseRedirect('/account/?tab=withdrawals')


# ==================== INVESTMENT VIEWS ====================

@login_required(login_url='XMR:signupin')
def investments(request):
    """View all available investments"""
    
    # ===== AUTO PAYOUT CHECK =====
    # Check and process any due payouts when user visits investments page
    check_user_payouts(request.user)
    # =============================
    
    # Get active tokens
    active_tokens = Token.objects.filter(status='ACTIVE').order_by('token_number')
    
    # Get user's investments
    user_investments_all = Investment.objects.filter(
        user=request.user
    ).select_related('token').order_by('-created_at')
    
    # Separate active and completed for display
    active_investments = user_investments_all.filter(status='ACTIVE')
    completed_investments = user_investments_all.filter(status='COMPLETED')
    
    # Get wallet for balance check
    wallet = request.user.wallet
    
    # Calculate totals
    total_invested = active_investments.aggregate(total=Sum('amount'))['total'] or 0
    total_earned = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='PROFIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    # Get next payout days
    next_payout = active_investments.order_by('end_date').first()
    next_payout_days = 0
    if next_payout:
        next_payout_days = (next_payout.end_date - timezone.now()).days
        if next_payout_days < 0:
            next_payout_days = 0
    
    # Get user's purchase history for each token (for max purchase limits)
    user_token_purchases = {}
    for token in active_tokens:
        user_token_purchases[token.id] = Investment.objects.filter(
            user=request.user,
            token=token
        ).count()
    
    context = {
        'active_tokens': active_tokens,
        'active_investments': active_investments,
        'completed_investments': completed_investments,
        'user_investments': user_investments_all,
        'wallet': wallet,
        'available_balance': wallet.available_balance(),
        'locked_balance': wallet.locked_balance,
        'total_balance': wallet.balance + wallet.locked_balance,
        'total_invested': total_invested,
        'total_earned': total_earned,
        'next_payout_days': next_payout_days,
        'user_token_purchases': user_token_purchases,
    }
    return render(request, 'investments.html', context)


@login_required(login_url='XMR:signupin')
def investment_detail(request, token_id):
    """Redirect to investments page with token details modal"""
    from django.urls import reverse
    return redirect(f"{reverse('XMR:investments')}?token={token_id}")


@login_required(login_url='XMR:signupin')
@transaction.atomic
def buy_investment(request, token_id):
    """
    Process investment purchase with atomic transaction
    Moves money from available balance to locked balance
    """
    if request.method != 'POST':
        return redirect('XMR:investment_detail', token_id=token_id)
    
    # Log the attempt
    logger.info(f"Investment attempt by user {request.user.username} for token {token_id}")
    
    try:
        # Select token with lock to prevent race conditions
        token = Token.objects.select_for_update().get(id=token_id)
        wallet = Wallet.objects.select_for_update().get(user=request.user)
        
        # DEBUG LOGGING
        logger.debug(f"User {request.user.username} - Available: {wallet.balance}, Locked: {wallet.locked_balance}")
        
        # Validate token is available
        if token.status != 'ACTIVE':
            messages.error(request, 'This token is not currently active')
            return redirect('XMR:investments')
        
        if not token.is_available():
            messages.error(request, 'This token is sold out')
            return redirect('XMR:investments')
        
        # Check minimum investment
        amount = token.minimum_investment
        
        # Check available balance (balance field)
        if wallet.balance < amount:
            messages.error(request, f'Insufficient available balance. You need {amount} KSH, but you have {wallet.balance} KSH available')
            logger.warning(f"Insufficient balance for user {request.user.username}: Have {wallet.balance}, Need {amount}")
            return redirect('XMR:investments')
        
        # Check max purchases
        if token.max_purchases_per_user:
            user_purchases = Investment.objects.filter(
                user=request.user,
                token=token
            ).count()
            if user_purchases >= token.max_purchases_per_user:
                messages.error(request, f'You have reached the maximum purchases for this token')
                return redirect('XMR:investments')
        
        # Create investment - this will move money from available to locked
        investment = Investment.objects.create(
            user=request.user,
            token=token,
            amount=amount
        )
        
        # Refresh wallet to get updated balances
        wallet.refresh_from_db()
        
        # Verify investment was created successfully
        if not investment.id:
            raise IntegrityError("Investment creation failed - no ID generated")
        
        # Log success
        logger.info(f"✅ Investment created: ID {investment.id} for user {request.user.username}")
        logger.debug(f"New wallet state - Available: {wallet.balance}, Locked: {wallet.locked_balance}")
        
        # Create success message with details
        success_message = (
            f"Successfully invested in {token.name}! "
            f"Amount: {amount} KSH, "
            f"Daily Return: {token.daily_return} KSH, "
            f"Duration: {token.return_days} days"
        )
        messages.success(request, success_message)
        
        # Log the investment
        SystemLog.objects.create(
            log_type='INFO',
            user=request.user,
            action='INVESTMENT_PURCHASED',
            description=f'Purchased {token.name} for {amount} KSH. Investment ID: {investment.id}'
        )
        
    except Token.DoesNotExist:
        messages.error(request, 'Token not found')
        logger.error(f"Token {token_id} not found")
        return redirect('XMR:investments')
        
    except ValidationError as e:
        messages.error(request, str(e))
        logger.error(f"ValidationError in investment: {str(e)}")
        transaction.set_rollback(True)
        
    except IntegrityError as e:
        messages.error(request, 'Investment creation failed due to database error. Please try again.')
        logger.error(f"IntegrityError in investment: {str(e)}", exc_info=True)
        transaction.set_rollback(True)
        
    except Exception as e:
        messages.error(request, f'Error processing investment: {str(e)}')
        logger.error(f"Unexpected error in investment: {str(e)}", exc_info=True)
        transaction.set_rollback(True)
    
    return redirect('XMR:investments')


# ==================== ADMIN VIEWS ====================

@login_required(login_url='XMR:signupin')
def myadmin(request):
    """Consolidated admin dashboard with all management features"""
    if not request.user.is_staff:
        messages.error(request, 'You are not authorized to access the admin area.')
        return redirect('XMR:account')
    
    from django.db.models.functions import TruncDate, TruncMonth
    
    # Get current date for filters
    today = timezone.now().date()
    week_ago = today - timedelta(days=7)
    
    # ========== DASHBOARD STATS ==========
    dashboard_stats = {
        'total_users': User.objects.count(),
        'new_users_today': User.objects.filter(date_joined__date=today).count(),
        'new_users_week': User.objects.filter(date_joined__date__gte=week_ago).count(),
        'verified_users': UserProfile.objects.filter(phone_verified=True).count(),
        
        'total_deposits': float(Transaction.objects.filter(
            transaction_type='DEPOSIT', status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or 0),
        
        'total_withdrawals': float(Transaction.objects.filter(
            transaction_type='WITHDRAWAL', status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or 0),
        
        'total_profits_paid': float(Transaction.objects.filter(
            transaction_type='PROFIT', status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or 0),
        
        'total_system_balance': float(Wallet.objects.aggregate(
            total=Sum('balance')
        )['total'] or 0),
        
        'total_locked_balance': float(Wallet.objects.aggregate(
            total=Sum('locked_balance')
        )['total'] or 0),
        
        'total_system_assets': float(Wallet.objects.aggregate(
            total=Sum('balance') + Sum('locked_balance')
        )['total'] or 0),
        
        'pending_deposits': MpesaPayment.objects.filter(status='PENDING').count(),
        'pending_withdrawals': WithdrawalRequest.objects.filter(status='PENDING').count(),
        'pending_kyc': UserProfile.objects.filter(
            Q(id_front_image__isnull=False) | 
            Q(id_back_image__isnull=False) | 
            Q(selfie_with_id__isnull=False)
        ).exclude(phone_verified=True, id_verified=True).count(),
        
        'active_investments': Investment.objects.filter(status='ACTIVE').count(),
        'completed_investments': Investment.objects.filter(status='COMPLETED').count(),
        'total_invested': float(Investment.objects.filter(
            status='ACTIVE'
        ).aggregate(total=Sum('amount'))['total'] or 0),
    }
    
    # Chart data (last 7 days deposits)
    daily_deposits = []
    for i in range(7):
        date = today - timedelta(days=i)
        total = Transaction.objects.filter(
            transaction_type='DEPOSIT',
            status='COMPLETED',
            created_at__date=date
        ).aggregate(total=Sum('amount'))['total'] or 0
        daily_deposits.append({
            'date': date.strftime('%Y-%m-%d'),
            'total': float(total)
        })
    
    # ========== DEPOSITS DATA ==========
    deposit_status = request.GET.get('deposit_status', 'PENDING')
    deposits = MpesaPayment.objects.filter(
        status=deposit_status
    ).select_related('user', 'user__profile').order_by('-created_at')[:50]
    
    deposits_data = []
    for d in deposits:
        deposits_data.append({
            'id': d.id,
            'user': d.user.username,
            'user_id': d.user.id,
            'amount': float(d.amount),
            'phone': d.phone_number,
            'mpesa_code': d.mpesa_code,
            'status': d.status,
            'created_at': d.created_at.strftime('%Y-%m-%d %H:%M'),
            'has_screenshot': bool(d.mpesa_screenshot),
            'mpesa_screenshot_url': d.mpesa_screenshot.url if d.mpesa_screenshot else None,
        })
    
    # ========== WITHDRAWALS DATA ==========
    withdrawal_status = request.GET.get('withdrawal_status', 'PENDING')
    withdrawals = WithdrawalRequest.objects.filter(
        status=withdrawal_status
    ).select_related('user', 'user__wallet').order_by('-created_at')[:50]
    
    withdrawals_data = []
    for w in withdrawals:
        withdrawals_data.append({
            'id': w.id,
            'request_id': w.request_id,
            'user': w.user.username,
            'user_id': w.user.id,
            'amount': float(w.amount),
            'net_amount': float(w.net_amount),
            'tax': float(w.tax_amount),
            'method': w.payment_method,
            'phone': w.phone_number,
            'status': w.status,
            'created_at': w.created_at.strftime('%Y-%m-%d %H:%M'),
        })
    
    # ========== INVESTMENTS DATA ==========
    investment_status = request.GET.get('investment_status', '')
    investments_query = Investment.objects.select_related(
        'user', 'token'
    ).order_by('-created_at')
    
    if investment_status:
        investments_query = investments_query.filter(status=investment_status)
    
    # Paginate investments
    investment_paginator = Paginator(investments_query, 50)
    investment_page = request.GET.get('investment_page', 1)
    investments_page = investment_paginator.get_page(investment_page)
    
    investments_data = []
    for inv in investments_page:
        # Calculate progress percentage
        total_days = inv.token.return_days
        completed_days = total_days - inv.remaining_payouts
        progress_percentage = (completed_days / total_days) * 100 if total_days > 0 else 0
        
        investments_data.append({
            'id': inv.id,
            'investment_id': inv.investment_id,
            'user': inv.user.username,
            'user_id': inv.user.id,
            'token_id': inv.token.id,
            'token_name': inv.token.name,
            'token_display_name': inv.token.display_name,
            'amount': float(inv.amount),
            'daily_return': float(inv.daily_return),
            'start_date': inv.start_date.strftime('%Y-%m-%d %H:%M'),
            'end_date': inv.end_date.strftime('%Y-%m-%d %H:%M'),
            'last_payout_date': inv.last_payout_date.strftime('%Y-%m-%d %H:%M') if inv.last_payout_date else None,
            'status': inv.status,
            'total_paid': float(inv.total_paid),
            'remaining_payouts': inv.remaining_payouts,
            'progress_percentage': round(progress_percentage, 1),
            'transaction_id': inv.transaction.id if inv.transaction else None,
        })
    
    # ========== TRANSACTIONS DATA ==========
    transaction_type = request.GET.get('transaction_type', '')
    transaction_status = request.GET.get('transaction_status', '')
    
    transactions_query = Transaction.objects.select_related(
        'wallet__user', 'investment', 'withdrawal'
    ).order_by('-created_at')
    
    if transaction_type:
        transactions_query = transactions_query.filter(transaction_type=transaction_type)
    if transaction_status:
        transactions_query = transactions_query.filter(status=transaction_status)
    
    # Paginate transactions
    transaction_paginator = Paginator(transactions_query, 50)
    transaction_page = request.GET.get('transaction_page', 1)
    transactions_page = transaction_paginator.get_page(transaction_page)
    
    transactions_data = []
    for t in transactions_page:
        transactions_data.append({
            'id': t.id,
            'transaction_id': t.transaction_id,
            'user': t.wallet.user.username,
            'user_id': t.wallet.user.id,
            'type': t.transaction_type,
            'amount': float(t.amount),
            'status': t.status,
            'description': t.description,
            'created_at': t.created_at.strftime('%Y-%m-%d %H:%M'),
            'processed_by': t.processed_by.username if t.processed_by else None,
            'processed_at': t.processed_at.strftime('%Y-%m-%d %H:%M') if t.processed_at else None,
            'investment_id': t.investment.id if t.investment else None,
            'withdrawal_id': t.withdrawal.id if t.withdrawal else None,
        })
    
    # ========== USERS DATA ==========
    user_search = request.GET.get('user_search', '')
    user_verified = request.GET.get('user_verified', '')
    user_banned = request.GET.get('user_banned', '')
    
    users_query = User.objects.select_related('profile', 'wallet').order_by('-date_joined')
    
    if user_search:
        users_query = users_query.filter(
            Q(username__icontains=user_search) |
            Q(email__icontains=user_search) |
            Q(first_name__icontains=user_search) |
            Q(last_name__icontains=user_search) |
            Q(profile__phone_number__icontains=user_search)
        )
    
    if user_verified:
        users_query = users_query.filter(profile__phone_verified=(user_verified == 'verified'))
    
    if user_banned:
        users_query = users_query.filter(profile__is_banned=(user_banned == 'banned'))
    
    user_paginator = Paginator(users_query, 20)
    user_page = request.GET.get('user_page', 1)
    users_page = user_paginator.get_page(user_page)
    
    users_data = []
    for u in users_page:
        users_data.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'first_name': u.first_name,
            'last_name': u.last_name,
            'phone': u.profile.phone_number,
            'balance': float(u.wallet.balance) if hasattr(u, 'wallet') and u.wallet.balance else 0,
            'locked_balance': float(u.wallet.locked_balance) if hasattr(u, 'wallet') and u.wallet.locked_balance else 0,
            'total_balance': float(u.wallet.balance + u.wallet.locked_balance) if hasattr(u, 'wallet') else 0,
            'phone_verified': u.profile.phone_verified,
            'id_verified': u.profile.id_verified,
            'is_banned': u.profile.is_banned,
            'date_joined': u.date_joined.strftime('%Y-%m-%d'),
            'referral_code': u.profile.referral_code,
            'active_investments': Investment.objects.filter(user=u, status='ACTIVE').count(),
            'total_invested': float(Investment.objects.filter(user=u, status='ACTIVE').aggregate(total=Sum('amount'))['total'] or 0),
        })
    
    # ========== TOKENS DATA ==========
    tokens = Token.objects.all().order_by('token_number')
    tokens_data = []
    for t in tokens:
        roi = float((t.total_return / t.minimum_investment) * 100) if t.minimum_investment and t.minimum_investment > 0 else 0
        
        tokens_data.append({
            'id': t.id,
            'name': t.name,
            'display_name': t.display_name,
            'token_number': t.token_number,
            'minimum_investment': float(t.minimum_investment) if t.minimum_investment else 0,
            'daily_return': float(t.daily_return) if t.daily_return else 0,
            'return_days': t.return_days,
            'total_return': float(t.total_return) if t.total_return else 0,
            'status': t.status,
            'max_purchases_per_user': t.max_purchases_per_user,
            'total_supply': t.total_supply,
            'purchased_count': t.purchased_count,
            'is_available': t.is_available(),
            'roi': roi,
            'description': t.description or '',
            'icon': t.icon or '',
            'color': t.color or 'primary',
        })
    
    # ========== KYC DATA ==========
    pending_kyc = UserProfile.objects.filter(
        Q(id_front_image__isnull=False) |
        Q(id_back_image__isnull=False) |
        Q(selfie_with_id__isnull=False)
    ).filter(
        Q(phone_verified=False) | Q(id_verified=False)
    ).select_related('user').order_by('-updated_at')[:50]
    
    kyc_data = []
    for k in pending_kyc:
        kyc_data.append({
            'id': k.id,
            'user_id': k.user.id,
            'username': k.user.username,
            'full_name': k.national_id_name or f"{k.user.first_name} {k.user.last_name}",
            'phone': k.phone_number,
            'phone_verified': k.phone_verified,
            'id_verified': k.id_verified,
            'has_id_front': bool(k.id_front_image),
            'has_id_back': bool(k.id_back_image),
            'has_selfie': bool(k.selfie_with_id),
            'id_front_url': k.id_front_image.url if k.id_front_image else None,
            'id_back_url': k.id_back_image.url if k.id_back_image else None,
            'selfie_url': k.selfie_with_id.url if k.selfie_with_id else None,
            'submitted_at': k.updated_at.strftime('%Y-%m-%d %H:%M'),
        })
    
    # ========== SYSTEM LOGS DATA ==========
    log_type = request.GET.get('log_type', '')
    log_user = request.GET.get('log_user', '')
    
    logs_query = SystemLog.objects.all().select_related('user').order_by('-created_at')
    
    if log_type:
        logs_query = logs_query.filter(log_type=log_type)
    if log_user:
        logs_query = logs_query.filter(user_id=log_user)
    
    log_paginator = Paginator(logs_query, 50)
    log_page = request.GET.get('log_page', 1)
    logs_page = log_paginator.get_page(log_page)
    
    logs_data = []
    for l in logs_page:
        logs_data.append({
            'id': l.id,
            'type': l.log_type,
            'user': l.user.username if l.user else 'System',
            'action': l.action,
            'description': l.description,
            'ip': l.ip_address,
            'created_at': l.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        })
    
    # Users for log filter dropdown
    log_users = User.objects.filter(
        id__in=SystemLog.objects.values_list('user_id', flat=True).distinct()
    ).values('id', 'username')
    
    # ========== SYSTEM CONFIG ==========
    configs = {c.key: c.value for c in SystemConfig.objects.all()}
    
    default_configs = {
        'min_deposit': 800,
        'min_withdrawal': 200,
        'withdrawal_tax': 5,
        'referral_commission': 5,
        'mpesa_paybill': '123456',
        'mpesa_account': 'INVEST',
        'site_name': 'XMR Investments',
        'support_email': 'support@example.com',
        'support_phone': '0712345678',
    }
    
    for key, value in default_configs.items():
        if key not in configs:
            configs[key] = value
    
    # Get active tab from URL or default to dashboard
    active_tab = request.GET.get('tab', 'dashboard')
    
    context = {
        # Dashboard stats
        'dashboard_stats': dashboard_stats,
        'daily_deposits': json.dumps(daily_deposits),
        
        # Deposits
        'deposits_data': deposits_data,
        'deposits': json.dumps(deposits_data),
        'deposit_status_choices': [s[0] for s in MpesaPayment.PAYMENT_STATUS],
        'current_deposit_status': deposit_status,
        
        # Withdrawals
        'withdrawals_data': withdrawals_data,
        'withdrawals': json.dumps(withdrawals_data),
        'withdrawal_status_choices': [s[0] for s in WithdrawalRequest.WITHDRAWAL_STATUS],
        'current_withdrawal_status': withdrawal_status,
        
        # Investments
        'investments_data': investments_data,
        'investments': json.dumps(investments_data),
        'investment_status_choices': [s[0] for s in Investment.INVESTMENT_STATUS],
        'current_investment_status': investment_status,
        'investments_pagination': {
            'current_page': investments_page.number,
            'total_pages': investments_page.paginator.num_pages,
            'total_items': investments_page.paginator.count,
            'has_next': investments_page.has_next(),
            'has_previous': investments_page.has_previous(),
        },
        
        # Transactions
        'transactions_data': transactions_data,
        'transactions': json.dumps(transactions_data),
        'transaction_type_choices': [s[0] for s in Transaction.TRANSACTION_TYPES],
        'transaction_status_choices': [s[0] for s in Transaction.STATUS_CHOICES],
        'current_transaction_type': transaction_type,
        'current_transaction_status': transaction_status,
        'transactions_pagination': {
            'current_page': transactions_page.number,
            'total_pages': transactions_page.paginator.num_pages,
            'total_items': transactions_page.paginator.count,
            'has_next': transactions_page.has_next(),
            'has_previous': transactions_page.has_previous(),
        },
        
        # Users
        'users_data': users_data,
        'users': json.dumps(users_data),
        'users_pagination': {
            'current_page': users_page.number,
            'total_pages': users_page.paginator.num_pages,
            'total_items': users_page.paginator.count,
            'has_next': users_page.has_next(),
            'has_previous': users_page.has_previous(),
        },
        
        # Tokens
        'tokens_data': tokens_data,
        'tokens': json.dumps(tokens_data),
        'token_status_choices': [s[0] for s in Token.TOKEN_STATUS],
        
        # KYC
        'kyc_pending_data': kyc_data,
        'kyc_pending': json.dumps(kyc_data),
        
        # Logs
        'logs_data': logs_data,
        'logs': json.dumps(logs_data),
        'logs_pagination': {
            'current_page': logs_page.number,
            'total_pages': logs_page.paginator.num_pages,
            'total_items': logs_page.paginator.count,
            'has_next': logs_page.has_next(),
            'has_previous': logs_page.has_previous(),
        },
        'log_users': list(log_users),
        'log_type_choices': [l[0] for l in SystemLog.LOG_TYPES],
        
        # Settings
        'configs': configs,
        
        # Active tab
        'active_tab': active_tab,
    }
    
    return render(request, 'admin.html', context)


# ==================== ADMIN API ENDPOINTS ====================

@login_required(login_url='XMR:signupin')
def admin_api(request):
    """API endpoint for admin actions"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    action = request.POST.get('action')
    
    # ========== DEPOSIT ACTIONS ==========
    if action == 'verify_deposit':
        deposit_id = request.POST.get('deposit_id')
        deposit = get_object_or_404(MpesaPayment, id=deposit_id)
        try:
            deposit.verify(request.user)
            return JsonResponse({'success': True, 'message': f'Deposit of {deposit.amount} KSH verified'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    elif action == 'reject_deposit':
        deposit_id = request.POST.get('deposit_id')
        reason = request.POST.get('reason', 'No reason provided')
        deposit = get_object_or_404(MpesaPayment, id=deposit_id)
        try:
            deposit.reject(request.user, reason)
            return JsonResponse({'success': True, 'message': 'Deposit rejected'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    # ========== WITHDRAWAL ACTIONS ==========
    elif action == 'process_withdrawal':
        withdrawal_id = request.POST.get('withdrawal_id')
        withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id)
        try:
            withdrawal.process(request.user)
            return JsonResponse({'success': True, 'message': 'Withdrawal marked as processing'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    elif action == 'complete_withdrawal':
        withdrawal_id = request.POST.get('withdrawal_id')
        transaction_code = request.POST.get('transaction_code')
        if not transaction_code:
            return JsonResponse({'success': False, 'error': 'Transaction code required'})
        
        withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id)
        try:
            withdrawal.complete(request.user, transaction_code)
            return JsonResponse({'success': True, 'message': 'Withdrawal completed'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    elif action == 'reject_withdrawal':
        withdrawal_id = request.POST.get('withdrawal_id')
        reason = request.POST.get('reason', 'No reason provided')
        withdrawal = get_object_or_404(WithdrawalRequest, id=withdrawal_id)
        try:
            withdrawal.reject(request.user, reason)
            return JsonResponse({'success': True, 'message': 'Withdrawal rejected'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    # ========== USER ACTIONS ==========
    elif action == 'toggle_user_ban':
        user_id = request.POST.get('user_id')
        reason = request.POST.get('reason', 'No reason provided')
        user = get_object_or_404(User, id=user_id)
        profile = user.profile
        profile.is_banned = not profile.is_banned
        if profile.is_banned:
            profile.ban_reason = reason
        else:
            profile.ban_reason = None
        profile.save()
        return JsonResponse({
            'success': True,
            'is_banned': profile.is_banned,
            'message': f'User {"banned" if profile.is_banned else "unbanned"}'
        })
    
    elif action == 'verify_user_phone':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(User, id=user_id)
        user.profile.phone_verified = True
        user.profile.save()
        return JsonResponse({'success': True, 'message': 'Phone verified'})
    
    elif action == 'verify_user_id':
        user_id = request.POST.get('user_id')
        user = get_object_or_404(User, id=user_id)
        user.profile.id_verified = True
        user.profile.save()
        return JsonResponse({'success': True, 'message': 'ID verified'})
    
    elif action == 'adjust_balance':
        user_id = request.POST.get('user_id')
        amount = request.POST.get('amount')
        description = request.POST.get('description', 'Admin adjustment')
        adjust_type = request.POST.get('adjust_type', 'add')  # 'add' or 'subtract'
        
        try:
            amount = Decimal(amount)
            if adjust_type == 'subtract':
                amount = -amount
                
            user = get_object_or_404(User, id=user_id)
            
            with transaction.atomic():
                wallet = Wallet.objects.select_for_update().get(user=user)
                
                # Check if subtracting would make balance negative
                if amount < 0 and wallet.balance < abs(amount):
                    return JsonResponse({
                        'success': False, 
                        'error': f'Cannot subtract {abs(amount)} KSH. Available balance is only {wallet.balance} KSH'
                    })
                
                trans = Transaction.objects.create(
                    wallet=wallet,
                    transaction_type='ADJUSTMENT',
                    amount=abs(amount),
                    description=description,
                    status='COMPLETED',
                    processed_by=request.user,
                    processed_at=timezone.now()
                )
                
                wallet.balance += amount
                wallet.save()
            
            return JsonResponse({
                'success': True,
                'new_balance': float(wallet.balance),
                'new_locked': float(wallet.locked_balance),
                'message': f'{"Added" if amount > 0 else "Subtracted"} {abs(amount)} KSH to/from wallet'
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    # ========== TOKEN ACTIONS ==========
    elif action == 'create_token':
        try:
            name = request.POST.get('name')
            display_name = request.POST.get('display_name')
            
            token_number_str = request.POST.get('token_number')
            if not token_number_str:
                return JsonResponse({'success': False, 'error': 'Token number is required'})
            token_number = int(token_number_str)
            
            min_investment_str = request.POST.get('minimum_investment')
            if not min_investment_str:
                return JsonResponse({'success': False, 'error': 'Minimum investment is required'})
            minimum_investment = Decimal(min_investment_str)
            
            daily_return_str = request.POST.get('daily_return')
            if not daily_return_str:
                return JsonResponse({'success': False, 'error': 'Daily return is required'})
            daily_return = Decimal(daily_return_str)
            
            return_days_str = request.POST.get('return_days', '12')
            return_days = int(return_days_str)
            
            status = request.POST.get('status', 'INACTIVE')
            
            max_purchases_input = request.POST.get('max_purchases_per_user')
            max_purchases_per_user = int(max_purchases_input) if max_purchases_input else 1
            
            total_supply_input = request.POST.get('total_supply')
            total_supply = int(total_supply_input) if total_supply_input else None
            
            description = request.POST.get('description', '')
            icon = request.POST.get('icon', '')
            color = request.POST.get('color', 'primary')
            
            if token_number < 1 or token_number > 20:
                return JsonResponse({'success': False, 'error': 'Token number must be between 1 and 20'})
            
            if Token.objects.filter(token_number=token_number).exists():
                return JsonResponse({'success': False, 'error': f'Token number {token_number} already exists'})
            
            token = Token.objects.create(
                name=name,
                display_name=display_name,
                token_number=token_number,
                minimum_investment=minimum_investment,
                daily_return=daily_return,
                return_days=return_days,
                status=status,
                max_purchases_per_user=max_purchases_per_user,
                total_supply=total_supply,
                description=description,
                icon=icon,
                color=color,
            )
            
            return JsonResponse({
                'success': True, 
                'message': f'Token {token.name} created successfully',
                'token_id': token.id
            })
            
        except ValueError as e:
            return JsonResponse({'success': False, 'error': f'Invalid number format: {str(e)}'})
        except InvalidOperation as e:
            return JsonResponse({'success': False, 'error': f'Invalid decimal format: {str(e)}'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    elif action == 'update_token':
        token_id = request.POST.get('token_id')
        token = get_object_or_404(Token, id=token_id)
        
        try:
            token.name = request.POST.get('name')
            token.display_name = request.POST.get('display_name')
            
            token_number_str = request.POST.get('token_number')
            if token_number_str:
                new_token_number = int(token_number_str)
                if Token.objects.filter(token_number=new_token_number).exclude(id=token.id).exists():
                    return JsonResponse({'success': False, 'error': f'Token number {new_token_number} already exists'})
                token.token_number = new_token_number
            
            min_investment_str = request.POST.get('minimum_investment')
            if min_investment_str:
                token.minimum_investment = Decimal(min_investment_str)
            
            daily_return_str = request.POST.get('daily_return')
            if daily_return_str:
                token.daily_return = Decimal(daily_return_str)
            
            return_days_str = request.POST.get('return_days')
            if return_days_str:
                token.return_days = int(return_days_str)
            
            token.status = request.POST.get('status')
            
            max_purchases_input = request.POST.get('max_purchases_per_user')
            token.max_purchases_per_user = int(max_purchases_input) if max_purchases_input else None
            
            total_supply_input = request.POST.get('total_supply')
            token.total_supply = int(total_supply_input) if total_supply_input else None
            
            token.description = request.POST.get('description', '')
            token.icon = request.POST.get('icon', '')
            token.color = request.POST.get('color', 'primary')
            
            token.save()
            
            return JsonResponse({
                'success': True, 
                'message': f'Token {token.name} updated successfully'
            })
            
        except ValueError as e:
            return JsonResponse({'success': False, 'error': f'Invalid number format: {str(e)}'})
        except InvalidOperation as e:
            return JsonResponse({'success': False, 'error': f'Invalid decimal format: {str(e)}'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    # ========== KYC ACTIONS ==========
    elif action == 'verify_kyc_phone':
        profile_id = request.POST.get('profile_id')
        profile = get_object_or_404(UserProfile, id=profile_id)
        profile.phone_verified = True
        profile.save()
        
        SystemLog.objects.create(
            log_type='ADMIN_ACTION',
            user=request.user,
            action='KYC_PHONE_VERIFIED',
            description=f'Phone verified for user {profile.user.username}'
        )
        
        return JsonResponse({'success': True, 'message': 'Phone verified'})
    
    elif action == 'verify_kyc_id':
        profile_id = request.POST.get('profile_id')
        profile = get_object_or_404(UserProfile, id=profile_id)
        profile.id_verified = True
        profile.save()
        
        SystemLog.objects.create(
            log_type='ADMIN_ACTION',
            user=request.user,
            action='KYC_ID_VERIFIED',
            description=f'ID verified for user {profile.user.username}'
        )
        
        return JsonResponse({'success': True, 'message': 'ID verified'})
    
    elif action == 'verify_kyc_all':
        profile_id = request.POST.get('profile_id')
        profile = get_object_or_404(UserProfile, id=profile_id)
        profile.phone_verified = True
        profile.id_verified = True
        profile.save()
        
        SystemLog.objects.create(
            log_type='ADMIN_ACTION',
            user=request.user,
            action='KYC_FULLY_VERIFIED',
            description=f'User {profile.user.username} fully verified'
        )
        
        return JsonResponse({'success': True, 'message': 'User fully verified'})
    
    # ========== INVESTMENT RECOVERY ==========
    elif action == 'recover_investment':
        if not request.user.is_superuser:
            return JsonResponse({'success': False, 'error': 'Superuser required'})
        
        user_id = request.POST.get('user_id')
        amount = request.POST.get('amount')
        token_id = request.POST.get('token_id')
        
        try:
            with transaction.atomic():
                user = User.objects.get(id=user_id)
                token = Token.objects.get(id=token_id)
                wallet = Wallet.objects.select_for_update().get(user=user)
                
                # Check if investment already exists
                existing_investment = Investment.objects.filter(
                    user=user,
                    token=token,
                    amount=amount
                ).first()
                
                if existing_investment:
                    return JsonResponse({
                        'success': False,
                        'error': 'Investment already exists for this user'
                    })
                
                # Create the missing investment
                investment = Investment.objects.create(
                    user=user,
                    token=token,
                    amount=amount
                )
                
                # Create transaction if needed
                if not investment.transaction:
                    transaction_record = Transaction.objects.create(
                        wallet=wallet,
                        transaction_type='INVESTMENT',
                        amount=amount,
                        description=f"Recovered investment in {token.name}",
                        status='COMPLETED',
                        investment=investment,
                        processed_by=request.user
                    )
                    investment.transaction = transaction_record
                    investment.save(update_fields=['transaction'])
                
                return JsonResponse({
                    'success': True,
                    'message': f'Investment recovered for user {user.username}'
                })
                
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'})
        except Token.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Token not found'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    # ========== SETTINGS ACTIONS ==========
    elif action == 'update_settings':
        try:
            updated_keys = []
            for key, value in request.POST.items():
                if key.startswith('config_'):
                    config_key = key[7:]
                    config, created = SystemConfig.objects.get_or_create(key=config_key)
                    
                    if value.lower() == 'true':
                        config.value = True
                    elif value.lower() == 'false':
                        config.value = False
                    elif value.isdigit():
                        config.value = int(value)
                    else:
                        try:
                            config.value = float(value)
                        except ValueError:
                            config.value = value
                    
                    config.save()
                    updated_keys.append(config_key)
            
            SystemLog.objects.create(
                log_type='ADMIN_ACTION',
                user=request.user,
                action='SETTINGS_UPDATED',
                description=f'Updated settings: {", ".join(updated_keys)}'
            )
            
            return JsonResponse({
                'success': True, 
                'message': f'Settings updated successfully',
                'updated': updated_keys
            })
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'error': f'Invalid action: {action}'}, status=400)


# ==================== API VIEWS ====================

@login_required(login_url='XMR:signupin')
def api_wallet_balance(request):
    """API endpoint to get wallet balance"""
    wallet = request.user.wallet
    return JsonResponse({
        'balance': float(wallet.balance),
        'locked': float(wallet.locked_balance),
        'available': float(wallet.available_balance()),
        'total': float(wallet.balance + wallet.locked_balance),
    })


@login_required(login_url='XMR:signupin')
def api_investment_stats(request):
    """API endpoint to get investment statistics"""
    investments = Investment.objects.filter(user=request.user)
    
    active = investments.filter(status='ACTIVE')
    completed = investments.filter(status='COMPLETED')
    
    total_invested = active.aggregate(total=Sum('amount'))['total'] or 0
    total_earned = Transaction.objects.filter(
        wallet=request.user.wallet,
        transaction_type='PROFIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    next_payout = active.order_by('end_date').first()
    next_payout_data = None
    if next_payout:
        next_payout_data = {
            'token': next_payout.token.name,
            'amount': float(next_payout.daily_return),
            'days_left': next_payout.remaining_payouts,
            'end_date': next_payout.end_date.strftime('%Y-%m-%d'),
        }
    
    return JsonResponse({
        'active_count': active.count(),
        'completed_count': completed.count(),
        'total_invested': float(total_invested),
        'total_earned': float(total_earned),
        'next_payout': next_payout_data,
    })


# ==================== HELPER FUNCTIONS ====================

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def clean_phone_number(phone):
    """Clean and format Kenyan phone number"""
    phone = re.sub(r'\D', '', phone)
    
    if phone.startswith('0') and len(phone) == 10:
        phone = '254' + phone[1:]
    elif phone.startswith('7') and len(phone) == 9:
        phone = '254' + phone
    elif phone.startswith('254') and len(phone) == 12:
        pass
    elif phone.startswith('+254') and len(phone) == 13:
        phone = phone[1:]
    
    return phone


def validate_phone_number(phone):
    """Validate Kenyan phone number"""
    pattern = r'^254[17]\d{8}$'
    return bool(re.match(pattern, phone))


# ==================== CRON JOBS / MANAGEMENT COMMANDS ====================

def process_daily_payouts():
    """Process daily payouts for all active investments"""
    print(f"{timezone.now()}: Starting daily payout processing...")
    
    active_investments = Investment.objects.filter(status='ACTIVE')
    
    processed = 0
    errors = 0
    
    for investment in active_investments:
        try:
            if investment.remaining_payouts > 0:
                investment.process_daily_payout()
                processed += 1
                
                if processed % 100 == 0:
                    print(f"Processed {processed} investments...")
                    
        except Exception as e:
            errors += 1
            print(f"Error processing investment {investment.id}: {str(e)}")
            logger.error(f"Daily payout error for investment {investment.id}: {str(e)}", exc_info=True)
    
    print(f"Completed: {processed} payouts processed, {errors} errors")
    
    SystemLog.objects.create(
        log_type='INFO',
        action='DAILY_PAYOUT',
        description=f'Daily payouts completed. Processed: {processed}, Errors: {errors}',
    )
    
    return processed, errors


def check_expired_investments():
    """Check for investments that have passed their end date"""
    expired = Investment.objects.filter(
        status='ACTIVE',
        end_date__lt=timezone.now()
    )
    
    count = 0
    for investment in expired:
        try:
            investment.complete_investment()  # This now returns principal to available balance
            count += 1
            
        except Exception as e:
            logger.error(f"Error marking investment {investment.id} as expired: {str(e)}", exc_info=True)
    
    if count > 0:
        SystemLog.objects.create(
            log_type='INFO',
            action='EXPIRED_INVESTMENTS',
            description=f'Marked {count} investments as expired/completed',
        )
    
    return count


# ==================== ADMIN TASK VIEWS ====================

@login_required(login_url='XMR:signupin')
def admin_trigger_payout(request):
    """Admin view to manually trigger payouts"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method == 'POST':
        # Process directly
        processed, errors = process_daily_payouts()
        
        SystemLog.objects.create(
            log_type='ADMIN_ACTION',
            user=request.user,
            action='MANUAL_PAYOUT_TRIGGERED',
            description=f'Admin manually triggered payouts. Processed: {processed}, Errors: {errors}'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Payouts processed: {processed} successful, {errors} errors',
            'processed': processed,
            'errors': errors
        })
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@login_required(login_url='XMR:signupin')
def admin_check_expired(request):
    """Admin view to manually check expired investments"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method == 'POST':
        count = check_expired_investments()
        
        return JsonResponse({
            'success': True,
            'message': f'Marked {count} investments as completed',
            'count': count
        })
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@login_required(login_url='XMR:signupin')
def admin_payout_stats(request):
    """Get statistics about payouts"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method not in ['GET', 'POST']:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    now = timezone.now()
    yesterday = now - timedelta(hours=24)
    
    # Get investment stats
    active_count = Investment.objects.filter(status='ACTIVE').count()
    due_count = Investment.objects.filter(
        status='ACTIVE',
        remaining_payouts__gt=0
    ).filter(
        Q(last_payout_date__isnull=True, created_at__lte=now - timedelta(hours=24)) |
        Q(last_payout_date__lte=now - timedelta(hours=24))
    ).count()
    
    # Get recent payouts
    recent_payouts = Transaction.objects.filter(
        transaction_type='PROFIT',
        created_at__gte=yesterday
    ).count()
    
    # Calculate missed payouts (investments that should have paid but haven't)
    missed_count = Investment.objects.filter(
        status='ACTIVE',
        remaining_payouts__gt=0,
        last_payout_date__lt=now - timedelta(hours=25)
    ).count()
    
    return JsonResponse({
        'success': True,
        'active_investments': active_count,
        'due_for_payout': due_count,
        'missed': missed_count,
        'payouts_last_24h': recent_payouts,
        'last_check': str(now)
    })


@login_required(login_url='XMR:signupin')
@transaction.atomic
def fix_all_wallets(request):
    """Fix all wallets with incorrect balances"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method not in ['GET', 'POST']:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    fixed_count = 0
    fixed_users = []
    errors = []
    
    try:
        for wallet in Wallet.objects.select_for_update().all():
            # Calculate what balances SHOULD be based on transactions
            total_deposits = Transaction.objects.filter(
                wallet=wallet,
                transaction_type='DEPOSIT',
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
            
            total_withdrawals = Transaction.objects.filter(
                wallet=wallet,
                transaction_type='WITHDRAWAL',
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
            
            total_profits = Transaction.objects.filter(
                wallet=wallet,
                transaction_type='PROFIT',
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
            
            total_referral_bonuses = Transaction.objects.filter(
                wallet=wallet,
                transaction_type='REFERRAL_BONUS',
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
            
            total_adjustments = Transaction.objects.filter(
                wallet=wallet,
                transaction_type='ADJUSTMENT',
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
            
            # Calculate locked balance from active investments
            active_investments = Investment.objects.filter(
                user=wallet.user,
                status='ACTIVE'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
            
            # Total earnings should be profits + referral bonuses
            correct_total_earned = total_profits + total_referral_bonuses
            
            # Available balance should be: deposits + profits + referral_bonuses + adjustments - withdrawals
            # Note: When investing, money moves from balance to locked_balance, so it's already accounted for
            correct_balance = total_deposits + total_profits + total_referral_bonuses + total_adjustments - total_withdrawals
            
            # Track if anything changed
            changes = {}
            
            if wallet.balance != correct_balance:
                changes['balance'] = f"{wallet.balance} → {correct_balance}"
                wallet.balance = correct_balance
            
            if wallet.locked_balance != active_investments:
                changes['locked_balance'] = f"{wallet.locked_balance} → {active_investments}"
                wallet.locked_balance = active_investments
            
            if wallet.total_earned != correct_total_earned:
                changes['total_earned'] = f"{wallet.total_earned} → {correct_total_earned}"
                wallet.total_earned = correct_total_earned
            
            if wallet.total_deposited != total_deposits:
                changes['total_deposited'] = f"{wallet.total_deposited} → {total_deposits}"
                wallet.total_deposited = total_deposits
            
            if wallet.total_withdrawn != total_withdrawals:
                changes['total_withdrawn'] = f"{wallet.total_withdrawn} → {total_withdrawals}"
                wallet.total_withdrawn = total_withdrawals
            
            if changes:
                wallet.save()
                fixed_count += 1
                fixed_users.append({
                    'username': wallet.user.username,
                    'changes': changes
                })
                
                SystemLog.objects.create(
                    log_type='ADMIN_ACTION',
                    user=request.user,
                    action='FIXED_WALLET_BALANCE',
                    description=f'Fixed wallet for {wallet.user.username}: {json.dumps(changes)}'
                )
                
                logger.info(f"Fixed wallet for {wallet.user.username}: {changes}")
        
        # Also check for investments that might be stuck in incorrect state
        stuck_investments = Investment.objects.filter(
            status='ACTIVE',
            remaining_payouts=0
        )
        for inv in stuck_investments:
            inv.complete_investment()
            logger.info(f"Completed stuck investment {inv.id} for user {inv.user.username}")
        
        # Check for investments that have passed end date but still active
        expired_investments = Investment.objects.filter(
            status='ACTIVE',
            end_date__lt=timezone.now()
        )
        for inv in expired_investments:
            inv.complete_investment()
            logger.info(f"Completed expired investment {inv.id} for user {inv.user.username}")
        
        message = f'Fixed {fixed_count} wallets with incorrect balances'
        if fixed_count > 0:
            message += f': {", ".join([u["username"] for u in fixed_users])}'
        
        return JsonResponse({
            'success': True,
            'message': message,
            'fixed_count': fixed_count,
            'fixed_users': fixed_users,
            'errors': errors
        })
        
    except Exception as e:
        logger.error(f"Error in fix_all_wallets: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# ==================== ADMIN INVESTMENT MANAGEMENT ====================

@login_required(login_url='XMR:signupin')
def admin_force_complete_investment(request, investment_id):
    """Admin view to force complete an investment"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        investment = get_object_or_404(Investment, id=investment_id)
        
        with transaction.atomic():
            # Complete the investment
            investment.complete_investment()
            
            SystemLog.objects.create(
                log_type='ADMIN_ACTION',
                user=request.user,
                action='FORCE_COMPLETE_INVESTMENT',
                description=f'Force completed investment {investment.investment_id} for user {investment.user.username}'
            )
            
            return JsonResponse({
                'success': True,
                'message': f'Investment {investment.investment_id} completed successfully',
                'user': investment.user.username,
                'amount': float(investment.amount)
            })
            
    except Exception as e:
        logger.error(f"Error force completing investment {investment_id}: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required(login_url='XMR:signupin')
def admin_force_payout(request, investment_id):
    """Admin view to force a single payout on an investment"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        investment = get_object_or_404(Investment, id=investment_id)
        
        with transaction.atomic():
            success = investment.process_daily_payout()
            
            if success:
                SystemLog.objects.create(
                    log_type='ADMIN_ACTION',
                    user=request.user,
                    action='FORCE_PAYOUT',
                    description=f'Force processed payout for investment {investment.investment_id}'
                )
                
                return JsonResponse({
                    'success': True,
                    'message': f'Payout processed successfully',
                    'remaining_payouts': investment.remaining_payouts,
                    'total_paid': float(investment.total_paid)
                })
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Could not process payout - investment may be completed or inactive'
                }, status=400)
            
    except Exception as e:
        logger.error(f"Error forcing payout for investment {investment_id}: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


# ==================== ADMIN USER MANAGEMENT ====================

@login_required(login_url='XMR:signupin')
def admin_user_detail(request, user_id):
    """Admin view to see detailed user information"""
    if not request.user.is_staff:
        messages.error(request, 'You are not authorized to access this page.')
        return redirect('XMR:account')
    
    user = get_object_or_404(User, id=user_id)
    
    # Get all user data
    profile = user.profile
    wallet = user.wallet
    
    # Get all transactions
    transactions = Transaction.objects.filter(
        wallet=wallet
    ).select_related('investment', 'withdrawal').order_by('-created_at')[:100]
    
    # Get all investments
    investments = Investment.objects.filter(
        user=user
    ).select_related('token').order_by('-created_at')
    
    # Get all deposits
    deposits = MpesaPayment.objects.filter(
        user=user
    ).order_by('-created_at')
    
    # Get all withdrawals
    withdrawals = WithdrawalRequest.objects.filter(
        user=user
    ).order_by('-created_at')
    
    # Calculate statistics
    total_deposits = transactions.filter(
        transaction_type='DEPOSIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    total_withdrawals = transactions.filter(
        transaction_type='WITHDRAWAL',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    total_profits = transactions.filter(
        transaction_type='PROFIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    total_referral_bonus = transactions.filter(
        transaction_type='REFERRAL_BONUS',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or 0
    
    active_investments = investments.filter(status='ACTIVE')
    total_invested = active_investments.aggregate(total=Sum('amount'))['total'] or 0
    
    context = {
        'user': user,
        'profile': profile,
        'wallet': wallet,
        'transactions': transactions,
        'investments': investments,
        'deposits': deposits,
        'withdrawals': withdrawals,
        'stats': {
            'total_deposits': float(total_deposits),
            'total_withdrawals': float(total_withdrawals),
            'total_profits': float(total_profits),
            'total_referral_bonus': float(total_referral_bonus),
            'total_invested': float(total_invested),
            'active_investments_count': active_investments.count(),
            'total_investments_count': investments.count(),
        }
    }
    
    return render(request, 'admin_user_detail.html', context)


# ==================== ADMIN SYSTEM MAINTENANCE ====================

@login_required(login_url='XMR:signupin')
def admin_system_status(request):
    """Admin view to check system status"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        # Get system statistics
        now = timezone.now()
        last_hour = now - timedelta(hours=1)
        last_day = now - timedelta(days=1)
        
        status = {
            'timestamp': str(now),
            'database': {
                'users_total': User.objects.count(),
                'users_active_last_hour': User.objects.filter(last_login__gte=last_hour).count(),
                'users_active_last_day': User.objects.filter(last_login__gte=last_day).count(),
            },
            'wallets': {
                'total_wallets': Wallet.objects.count(),
                'total_available_balance': float(Wallet.objects.aggregate(total=Sum('balance'))['total'] or 0),
                'total_locked_balance': float(Wallet.objects.aggregate(total=Sum('locked_balance'))['total'] or 0),
                'wallets_with_negative': Wallet.objects.filter(balance__lt=0).count(),
                'wallets_with_mismatch': check_for_wallet_mismatches(),
            },
            'investments': {
                'active': Investment.objects.filter(status='ACTIVE').count(),
                'completed': Investment.objects.filter(status='COMPLETED').count(),
                'total_invested': float(Investment.objects.filter(status='ACTIVE').aggregate(total=Sum('amount'))['total'] or 0),
                'due_for_payout': Investment.objects.filter(
                    status='ACTIVE',
                    remaining_payouts__gt=0
                ).filter(
                    Q(last_payout_date__isnull=True, created_at__lte=now - timedelta(hours=24)) |
                    Q(last_payout_date__lte=now - timedelta(hours=24))
                ).count(),
                'overdue': Investment.objects.filter(
                    status='ACTIVE',
                    remaining_payouts__gt=0,
                    last_payout_date__lt=now - timedelta(hours=25)
                ).count(),
            },
            'transactions': {
                'last_hour': Transaction.objects.filter(created_at__gte=last_hour).count(),
                'last_day': Transaction.objects.filter(created_at__gte=last_day).count(),
                'pending': Transaction.objects.filter(status='PENDING').count(),
                'failed': Transaction.objects.filter(status='FAILED').count(),
            },
            'deposits': {
                'pending': MpesaPayment.objects.filter(status='PENDING').count(),
                'verified_today': MpesaPayment.objects.filter(
                    status='VERIFIED',
                    verified_at__date=now.date()
                ).count(),
            },
            'withdrawals': {
                'pending': WithdrawalRequest.objects.filter(status='PENDING').count(),
                'processing': WithdrawalRequest.objects.filter(status='PROCESSING').count(),
                'completed_today': WithdrawalRequest.objects.filter(
                    status='COMPLETED',
                    processed_at__date=now.date()
                ).count(),
            },
            'kyc': {
                'pending': UserProfile.objects.filter(
                    Q(id_front_image__isnull=False) |
                    Q(id_back_image__isnull=False) |
                    Q(selfie_with_id__isnull=False)
                ).filter(
                    Q(phone_verified=False) | Q(id_verified=False)
                ).count(),
                'verified': UserProfile.objects.filter(phone_verified=True, id_verified=True).count(),
            }
        }
        
        return JsonResponse({'success': True, 'status': status})
        
    except Exception as e:
        logger.error(f"Error getting system status: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def check_for_wallet_mismatches():
    """Helper function to check for wallet balance mismatches"""
    mismatches = 0
    
    for wallet in Wallet.objects.all():
        # Calculate expected balance
        total_deposits = Transaction.objects.filter(
            wallet=wallet,
            transaction_type='DEPOSIT',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        total_withdrawals = Transaction.objects.filter(
            wallet=wallet,
            transaction_type='WITHDRAWAL',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        total_profits = Transaction.objects.filter(
            wallet=wallet,
            transaction_type='PROFIT',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        total_referral = Transaction.objects.filter(
            wallet=wallet,
            transaction_type='REFERRAL_BONUS',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        expected_balance = total_deposits + total_profits + total_referral - total_withdrawals
        
        if wallet.balance != expected_balance:
            mismatches += 1
    
    return mismatches


# ==================== EXPORT FUNCTIONS ====================

@login_required(login_url='XMR:signupin')
def export_transactions_csv(request):
    """Export transactions as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="transactions_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Transaction ID', 'User', 'Type', 'Amount', 'Status', 
        'Description', 'Created At', 'Processed At', 'Processed By'
    ])
    
    transactions = Transaction.objects.select_related(
        'wallet__user', 'processed_by'
    ).order_by('-created_at')[:5000]  # Limit to last 5000 for performance
    
    for t in transactions:
        writer.writerow([
            t.transaction_id,
            t.wallet.user.username,
            t.transaction_type,
            float(t.amount),
            t.status,
            t.description,
            t.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            t.processed_at.strftime('%Y-%m-%d %H:%M:%S') if t.processed_at else '',
            t.processed_by.username if t.processed_by else ''
        ])
    
    return response


@login_required(login_url='XMR:signupin')
def export_users_csv(request):
    """Export users as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="users_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow([
        'Username', 'Email', 'First Name', 'Last Name', 'Phone',
        'Balance', 'Locked Balance', 'Total Deposited', 'Total Withdrawn',
        'Total Earned', 'Phone Verified', 'ID Verified', 'Is Banned',
        'Date Joined', 'Last Login', 'Referral Code', 'Referred By'
    ])
    
    users = User.objects.select_related('profile', 'wallet').order_by('-date_joined')[:2000]
    
    for u in users:
        writer.writerow([
            u.username,
            u.email,
            u.first_name,
            u.last_name,
            u.profile.phone_number,
            float(u.wallet.balance) if hasattr(u, 'wallet') else 0,
            float(u.wallet.locked_balance) if hasattr(u, 'wallet') else 0,
            float(u.wallet.total_deposited) if hasattr(u, 'wallet') else 0,
            float(u.wallet.total_withdrawn) if hasattr(u, 'wallet') else 0,
            float(u.wallet.total_earned) if hasattr(u, 'wallet') else 0,
            'Yes' if u.profile.phone_verified else 'No',
            'Yes' if u.profile.id_verified else 'No',
            'Yes' if u.profile.is_banned else 'No',
            u.date_joined.strftime('%Y-%m-%d %H:%M:%S'),
            u.last_login.strftime('%Y-%m-%d %H:%M:%S') if u.last_login else '',
            u.profile.referral_code,
            u.profile.referred_by.user.username if u.profile.referred_by else ''
        ])
    
    return response


# ==================== DEBUGGING AND TESTING ====================

@login_required(login_url='XMR:signupin')
def debug_wallet(request, user_id=None):
    """Debug view to check wallet state (admin only)"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    if user_id:
        user = get_object_or_404(User, id=user_id)
    else:
        user = request.user
    
    wallet = user.wallet
    
    # Get all transactions
    deposits = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='DEPOSIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    withdrawals = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='WITHDRAWAL',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    profits = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='PROFIT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    referrals = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='REFERRAL_BONUS',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    adjustments = Transaction.objects.filter(
        wallet=wallet,
        transaction_type='ADJUSTMENT',
        status='COMPLETED'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    # Active investments
    active_investments = Investment.objects.filter(
        user=user,
        status='ACTIVE'
    )
    
    total_locked = active_investments.aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    # Expected calculations
    expected_balance = deposits + profits + referrals + adjustments - withdrawals
    expected_total_earned = profits + referrals
    
    debug_info = {
        'user': user.username,
        'wallet_state': {
            'current_balance': float(wallet.balance),
            'current_locked': float(wallet.locked_balance),
            'current_total_earned': float(wallet.total_earned),
            'current_total_deposited': float(wallet.total_deposited),
            'current_total_withdrawn': float(wallet.total_withdrawn),
        },
        'transaction_totals': {
            'deposits': float(deposits),
            'withdrawals': float(withdrawals),
            'profits': float(profits),
            'referrals': float(referrals),
            'adjustments': float(adjustments),
        },
        'expected_values': {
            'expected_balance': float(expected_balance),
            'expected_locked': float(total_locked),
            'expected_total_earned': float(expected_total_earned),
            'balance_match': wallet.balance == expected_balance,
            'locked_match': wallet.locked_balance == total_locked,
            'earned_match': wallet.total_earned == expected_total_earned,
        },
        'active_investments': [
            {
                'id': inv.id,
                'token': inv.token.name,
                'amount': float(inv.amount),
                'remaining_payouts': inv.remaining_payouts,
                'total_paid': float(inv.total_paid),
                'start_date': str(inv.start_date),
                'end_date': str(inv.end_date),
                'last_payout': str(inv.last_payout_date) if inv.last_payout_date else None,
            }
            for inv in active_investments
        ],
        'recent_transactions': [
            {
                'id': t.id,
                'type': t.transaction_type,
                'amount': float(t.amount),
                'status': t.status,
                'created': str(t.created_at),
                'description': t.description,
            }
            for t in Transaction.objects.filter(wallet=wallet).order_by('-created_at')[:20]
        ]
    }
    
    return JsonResponse(debug_info)


# ==================== ERROR HANDLERS ====================

def handler404(request, exception):
    """Custom 404 error handler"""
    return render(request, '404.html', status=404)


def handler500(request):
    """Custom 500 error handler"""
    return render(request, '500.html', status=500)


def handler403(request, exception):
    """Custom 403 error handler"""
    return render(request, '403.html', status=403)


def handler400(request, exception):
    """Custom 400 error handler"""
    return render(request, '400.html', status=400)


# ==================== HEALTH CHECK ====================

def health_check(request):
    """
    Simple health check endpoint for monitoring
    Returns 200 if system is operational
    """
    try:
        # Check database connectivity
        User.objects.exists()
        
        # Check if critical models are accessible
        Wallet.objects.exists()
        
        return JsonResponse({
            'status': 'healthy',
            'timestamp': str(timezone.now()),
            'database': 'connected'
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'unhealthy',
            'timestamp': str(timezone.now()),
            'error': str(e)
        }, status=500)


# ==================== INITIAL SETUP ====================

def initialize_system(request):
    """
    Initialize system with default data
    This should be run once during deployment
    """
    # Only allow in debug mode or via specific condition
    if not settings.DEBUG:
        return JsonResponse({'error': 'Not allowed in production'}, status=403)
    
    try:
        # Create default tokens if they don't exist
        default_tokens = [
            {
                'name': 'XMR-1',
                'display_name': 'Starter',
                'token_number': 1,
                'minimum_investment': 800,
                'daily_return': 100,
                'return_days': 12,
                'status': 'ACTIVE',
                'description': 'Perfect for beginners. Low entry, consistent returns.',
                'icon': 'fa-seedling',
                'color': 'success',
            },
            {
                'name': 'XMR-2',
                'display_name': 'Bronze',
                'token_number': 2,
                'minimum_investment': 2000,
                'daily_return': 280,
                'return_days': 12,
                'status': 'ACTIVE',
                'description': 'Solid returns with moderate investment.',
                'icon': 'fa-medal',
                'color': 'bronze',
            },
            {
                'name': 'XMR-3',
                'display_name': 'Silver',
                'token_number': 3,
                'minimum_investment': 5000,
                'daily_return': 750,
                'return_days': 12,
                'status': 'ACTIVE',
                'description': 'Premium returns for serious investors.',
                'icon': 'fa-gem',
                'color': 'secondary',
            },
            {
                'name': 'XMR-4',
                'display_name': 'Gold',
                'token_number': 4,
                'minimum_investment': 10000,
                'daily_return': 1600,
                'return_days': 12,
                'status': 'ACTIVE',
                'description': 'High-tier investment with maximum returns.',
                'icon': 'fa-crown',
                'color': 'warning',
            },
        ]
        
        created_tokens = []
        for token_data in default_tokens:
            token, created = Token.objects.get_or_create(
                name=token_data['name'],
                defaults=token_data
            )
            if created:
                created_tokens.append(token.name)
        
        # Create default system configs
        default_configs = {
            'min_deposit': 800,
            'min_withdrawal': 200,
            'withdrawal_tax': 5,
            'referral_commission': 5,
            'mpesa_paybill': '123456',
            'mpesa_account': 'INVEST',
            'site_name': 'XMR Investments',
            'support_email': 'support@example.com',
            'support_phone': '0712345678',
        }
        
        created_configs = []
        for key, value in default_configs.items():
            config, created = SystemConfig.objects.get_or_create(
                key=key,
                defaults={'value': value, 'description': f'Default {key}'}
            )
            if created:
                created_configs.append(key)
        
        # Create superuser if none exists
        if not User.objects.filter(is_superuser=True).exists():
            User.objects.create_superuser(
                username='admin',
                email='admin@example.com',
                password='Admin123!'
            )
            created_admin = True
        else:
            created_admin = False
        
        return JsonResponse({
            'success': True,
            'message': 'System initialized successfully',
            'created_tokens': created_tokens,
            'created_configs': created_configs,
            'created_admin': created_admin
        })
        
    except Exception as e:
        logger.error(f"System initialization error: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)





@login_required(login_url='XMR:signupin')
def export_deposits_csv(request):
    """Export deposits as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="deposits_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['ID', 'User', 'Amount', 'Phone', 'M-Pesa Code', 'Status', 'Created At'])
    
    deposits = MpesaPayment.objects.select_related('user').order_by('-created_at')[:5000]
    
    for d in deposits:
        writer.writerow([
            d.id,
            d.user.username,
            float(d.amount),
            d.phone_number,
            d.mpesa_code or '',
            d.status,
            d.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required(login_url='XMR:signupin')
def export_withdrawals_csv(request):
    """Export withdrawals as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="withdrawals_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Request ID', 'User', 'Amount', 'Net Amount', 'Tax', 'Method', 'Status', 'Created At'])
    
    withdrawals = WithdrawalRequest.objects.select_related('user').order_by('-created_at')[:5000]
    
    for w in withdrawals:
        writer.writerow([
            w.request_id,
            w.user.username,
            float(w.amount),
            float(w.net_amount),
            float(w.tax_amount),
            w.payment_method,
            w.status,
            w.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required(login_url='XMR:signupin')
def export_investments_csv(request):
    """Export investments as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="investments_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Investment ID', 'User', 'Token', 'Amount', 'Daily Return', 'Total Paid', 'Status', 'Start Date', 'End Date'])
    
    investments = Investment.objects.select_related('user', 'token').order_by('-created_at')[:5000]
    
    for inv in investments:
        writer.writerow([
            inv.investment_id,
            inv.user.username,
            inv.token.name,
            float(inv.amount),
            float(inv.daily_return),
            float(inv.total_paid),
            inv.status,
            inv.start_date.strftime('%Y-%m-%d %H:%M:%S'),
            inv.end_date.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required(login_url='XMR:signupin')
def export_tokens_csv(request):
    """Export tokens as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="tokens_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Token Number', 'Name', 'Display Name', 'Min Investment', 'Daily Return', 'Return Days', 'Status', 'Purchased Count'])
    
    tokens = Token.objects.all().order_by('token_number')
    
    for t in tokens:
        writer.writerow([
            t.token_number,
            t.name,
            t.display_name,
            float(t.minimum_investment) if t.minimum_investment else 0,
            float(t.daily_return) if t.daily_return else 0,
            t.return_days,
            t.status,
            t.purchased_count
        ])
    
    return response


@login_required(login_url='XMR:signupin')
def export_kyc_csv(request):
    """Export KYC requests as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    from django.db.models import Q
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="kyc_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['User', 'Full Name', 'Phone', 'Phone Verified', 'ID Verified', 'Has ID Front', 'Has ID Back', 'Has Selfie', 'Submitted At'])
    
    kyc_requests = UserProfile.objects.filter(
        Q(id_front_image__isnull=False) |
        Q(id_back_image__isnull=False) |
        Q(selfie_with_id__isnull=False)
    ).select_related('user').order_by('-updated_at')
    
    for k in kyc_requests:
        writer.writerow([
            k.user.username,
            k.national_id_name or f"{k.user.first_name} {k.user.last_name}",
            k.phone_number,
            'Yes' if k.phone_verified else 'No',
            'Yes' if k.id_verified else 'No',
            'Yes' if k.id_front_image else 'No',
            'Yes' if k.id_back_image else 'No',
            'Yes' if k.selfie_with_id else 'No',
            k.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required(login_url='XMR:signupin')
def export_logs_csv(request):
    """Export system logs as CSV"""
    if not request.user.is_staff:
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="logs_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Time', 'Type', 'User', 'Action', 'Description', 'IP Address'])
    
    logs = SystemLog.objects.select_related('user').order_by('-created_at')[:5000]
    
    for log in logs:
        writer.writerow([
            log.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            log.log_type,
            log.user.username if log.user else 'System',
            log.action,
            log.description,
            log.ip_address or ''
        ])
    
    return response






from django.conf import settings