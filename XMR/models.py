from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from django.db.models import Sum, Q
import random
import string
import uuid
from decimal import Decimal
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError

# ==================== BASE MODELS ====================

class TimeStampedModel(models.Model):
    """
    Abstract base model that provides self-updating 'created_at' and 'updated_at' fields.
    """
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UserProfile(TimeStampedModel):
    """
    Extended user profile with referral and verification system.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=20, db_index=True)
    national_id_name = models.CharField(max_length=100, blank=True, null=True)
    referral_code = models.CharField(max_length=10, unique=True, blank=True)
    referred_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='referrals')
    phone_verified = models.BooleanField(default=False)
    id_verified = models.BooleanField(default=False)
    
    # KYC Documents
    id_front_image = models.ImageField(upload_to='kyc/ids/front/', blank=True, null=True)
    id_back_image = models.ImageField(upload_to='kyc/ids/back/', blank=True, null=True)
    selfie_with_id = models.ImageField(upload_to='kyc/selfies/', blank=True, null=True)
    
    # Account status
    is_active = models.BooleanField(default=True)
    is_banned = models.BooleanField(default=False)
    ban_reason = models.TextField(blank=True, null=True)
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['referral_code']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['-created_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.referral_code:
            self.referral_code = self.generate_referral_code()
        super().save(*args, **kwargs)
    
    def generate_referral_code(self):
        """Generate unique referral code"""
        while True:
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            if not UserProfile.objects.filter(referral_code=code).exists():
                return code
    
    def get_referral_count(self):
        """Get total number of direct referrals"""
        return self.referrals.count()
    
    def get_total_referral_earnings(self):
        """Calculate total earnings from referrals"""
        return self.user.wallet.transactions.filter(
            transaction_type='REFERRAL_BONUS',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    def get_total_deposits(self):
        """Get total deposits made by user"""
        return self.user.wallet.transactions.filter(
            transaction_type='DEPOSIT',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
    
    def __str__(self):
        return f"{self.user.username} - {self.referral_code}"


# ==================== WALLET & TRANSACTIONS ====================

class Wallet(TimeStampedModel):
    """
    User's wallet for managing funds.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='wallet')
    balance = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))
    locked_balance = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))  # Funds in active investments
    total_deposited = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))
    total_withdrawn = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))
    total_earned = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))
    
    # Currency (default KSH)
    currency = models.CharField(max_length=3, default='KSH')
    
    class Meta:
        indexes = [
            models.Index(fields=['user', 'balance']),
        ]
    
    def available_balance(self):
        """Balance available for withdrawal/investment"""
        return self.balance - self.locked_balance
    
    def update_balances(self):
        """Recalculate balances from transactions"""
        deposits = self.transactions.filter(
            transaction_type='DEPOSIT',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        withdrawals = self.transactions.filter(
            transaction_type='WITHDRAWAL',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        earnings = self.transactions.filter(
            transaction_type='PROFIT',
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or Decimal('0')
        
        self.total_deposited = deposits
        self.total_withdrawn = withdrawals
        self.total_earned = earnings
        self.save()
    
    def __str__(self):
        return f"{self.user.username}'s Wallet - Balance: {self.balance} {self.currency}"


class Transaction(TimeStampedModel):
    """
    All financial transactions in the system.
    """
    TRANSACTION_TYPES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('INVESTMENT', 'Investment'),
        ('PROFIT', 'Profit'),
        ('REFERRAL_BONUS', 'Referral Bonus'),
        ('PENALTY', 'Penalty'),
        ('ADJUSTMENT', 'Admin Adjustment'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
        ('PROCESSING', 'Processing'),
    ]
    
    transaction_id = models.CharField(max_length=50, unique=True, default=uuid.uuid4, editable=False)
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPES, db_index=True)
    amount = models.DecimalField(max_digits=20, decimal_places=2, validators=[MinValueValidator(Decimal('0.01'))])
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING', db_index=True)
    description = models.CharField(max_length=255)
    
    # For related objects - FIXED: Added unique related_name to avoid clashes
    investment = models.ForeignKey('Investment', on_delete=models.SET_NULL, null=True, blank=True, related_name='transaction_entries')
    withdrawal = models.ForeignKey('WithdrawalRequest', on_delete=models.SET_NULL, null=True, blank=True, related_name='transaction_entries')
    
    # Metadata
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_transactions')
    processed_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['transaction_id']),
            models.Index(fields=['wallet', 'status']),
            models.Index(fields=['wallet', 'transaction_type']),
            models.Index(fields=['-created_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            self.transaction_id = f"TXN{timezone.now().strftime('%Y%m%d%H%M%S')}{random.randint(1000, 9999)}"
        super().save(*args, **kwargs)
    
    def process(self, admin_user=None):
        """Process a pending transaction"""
        if self.status != 'PENDING':
            raise ValidationError("Can only process pending transactions")
        
        self.status = 'COMPLETED'
        self.processed_by = admin_user
        self.processed_at = timezone.now()
        
        # Update wallet balance based on transaction type
        if self.transaction_type in ['DEPOSIT', 'PROFIT', 'REFERRAL_BONUS']:
            self.wallet.balance += self.amount
        elif self.transaction_type == 'WITHDRAWAL':
            if self.wallet.balance < self.amount:
                raise ValidationError("Insufficient balance")
            self.wallet.balance -= self.amount
        elif self.transaction_type == 'INVESTMENT':
            # Investment is handled in Investment model save method
            pass
        
        self.wallet.save()
        self.save()
    
    def __str__(self):
        return f"{self.transaction_id} - {self.transaction_type} - {self.amount}"


# ==================== MPESA INTEGRATION ====================

class MpesaPayment(TimeStampedModel):
    """
    M-Pesa payment tracking and verification.
    """
    PAYMENT_STATUS = [
        ('PENDING', 'Pending Verification'),
        ('VERIFIED', 'Verified'),
        ('REJECTED', 'Rejected'),
        ('PROCESSING', 'Processing'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='mpesa_payments')
    transaction = models.OneToOneField(Transaction, on_delete=models.CASCADE, related_name='mpesa_payment', null=True, blank=True)
    
    # Payment details
    amount = models.DecimalField(max_digits=20, decimal_places=2, validators=[MinValueValidator(Decimal('800.00'))])
    phone_number = models.CharField(max_length=15)  # Sender's phone
    
    # M-Pesa message/screenshot
    mpesa_message = models.TextField(help_text="Full M-Pesa confirmation message")
    mpesa_screenshot = models.ImageField(upload_to='mpesa/screenshots/%Y/%m/%d/', blank=True, null=True)
    
    # Extracted data from message
    mpesa_code = models.CharField(max_length=50, blank=True, null=True, db_index=True, 
                                   help_text="Extracted M-Pesa transaction code")
    transaction_date = models.DateTimeField(blank=True, null=True)
    sender_name = models.CharField(max_length=100, blank=True, null=True)
    
    # Status
    status = models.CharField(max_length=20, choices=PAYMENT_STATUS, default='PENDING', db_index=True)
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='verified_payments')
    verified_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True, null=True)
    
    # Admin notes
    admin_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['mpesa_code']),
            models.Index(fields=['user', 'status']),
            models.Index(fields=['-created_at']),
        ]
    
    def extract_mpesa_data(self):
        """
        Extract transaction code, date, and sender from M-Pesa message.
        Handles different M-Pesa message formats.
        """
        import re
        from datetime import datetime
        
        message = self.mpesa_message
        
        # Extract M-Pesa confirmation code (format: ABC123XYZ)
        code_patterns = [
            r'([A-Z0-9]{10,12})',  # Generic code
            r'Confirmation\.?([A-Z0-9]+)',  # With "Confirmation" prefix
            r'([A-Z0-9]+)\s+Confirmed',  # With "Confirmed" suffix
        ]
        
        for pattern in code_patterns:
            match = re.search(pattern, message)
            if match:
                self.mpesa_code = match.group(1)
                break
        
        # Extract amount
        amount_pattern = r'(?:Ksh|KES|KSh)[\s.]*([0-9,]+(?:\.[0-9]{2})?)'
        amount_match = re.search(amount_pattern, message, re.IGNORECASE)
        if amount_match:
            amount_str = amount_match.group(1).replace(',', '')
            extracted_amount = Decimal(amount_str)
            if abs(extracted_amount - self.amount) > Decimal('1.00'):  # Allow small difference
                # Flag for admin review
                self.admin_notes = f"Amount mismatch: Message shows {extracted_amount}"
        
        # Extract sender phone
        phone_pattern = r'(?:from|sender)[\s:]*0?(\d{9,12})'
        phone_match = re.search(phone_pattern, message, re.IGNORECASE)
        if phone_match:
            self.sender_name = phone_match.group(1)
        
        # Extract date
        date_patterns = [
            r'(\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}\s*(?:AM|PM)?)',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, message)
            if match:
                try:
                    # Try to parse date (simplified - would need more robust parsing)
                    self.transaction_date = timezone.now()  # Placeholder
                except:
                    pass
        
        self.save()
    
    def verify(self, admin_user):
        """Admin verification of M-Pesa payment"""
        if self.status != 'PENDING':
            raise ValidationError("Can only verify pending payments")
        
        self.status = 'VERIFIED'
        self.verified_by = admin_user
        self.verified_at = timezone.now()
        self.save()
        
        # Create deposit transaction
        transaction = Transaction.objects.create(
            wallet=self.user.wallet,
            transaction_type='DEPOSIT',
            amount=self.amount,
            description=f"M-Pesa deposit - {self.mpesa_code or 'Manual verification'}",
            status='COMPLETED'
        )
        transaction.processed_by = admin_user
        transaction.processed_at = timezone.now()
        transaction.save()
        
        # Link to this payment
        self.transaction = transaction
        self.save()
        
        # Update wallet
        wallet = self.user.wallet
        wallet.balance += self.amount
        wallet.total_deposited += self.amount
        wallet.save()
        
        # Process first deposit referral bonus
        if wallet.total_deposited == self.amount:  # First deposit
            self.process_referral_bonus()
        
        return transaction
    
    def process_referral_bonus(self):
        """Give 5% referral bonus to referrer on first deposit"""
        profile = self.user.profile
        if profile.referred_by:
            referrer = profile.referred_by.user
            bonus_amount = self.amount * Decimal('0.05')  # 5% bonus
            
            Transaction.objects.create(
                wallet=referrer.wallet,
                transaction_type='REFERRAL_BONUS',
                amount=bonus_amount,
                description=f"5% referral bonus from {self.user.username}'s first deposit",
                status='COMPLETED'
            )
            
            # Add to referrer's wallet
            referrer.wallet.balance += bonus_amount
            referrer.wallet.total_earned += bonus_amount
            referrer.wallet.save()
    
    def reject(self, admin_user, reason):
        """Reject a payment"""
        self.status = 'REJECTED'
        self.verified_by = admin_user
        self.verified_at = timezone.now()
        self.rejection_reason = reason
        self.save()
    
    def __str__(self):
        return f"M-Pesa {self.amount} - {self.user.username} - {self.status}"


# ==================== INVESTMENT TOKENS ====================

class Token(TimeStampedModel):
    """
    Investment token definitions (XMR-1 to XMR-20)
    """
    TOKEN_STATUS = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('COMING_SOON', 'Coming Soon'),
        ('SOLD_OUT', 'Sold Out'),
    ]
    
    name = models.CharField(max_length=20, unique=True)  # XMR-1, XMR-2, etc.
    display_name = models.CharField(max_length=50)
    token_number = models.IntegerField(unique=True, validators=[MinValueValidator(1), MaxValueValidator(20)])
    
    # Investment details
    minimum_investment = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('800.00'))
    daily_return = models.DecimalField(max_digits=10, decimal_places=2, help_text="Daily return in KSH")
    return_days = models.IntegerField(default=12, help_text="Number of days returns are paid")
    total_return = models.DecimalField(max_digits=20, decimal_places=2, editable=False)
    
    # Token status
    status = models.CharField(max_length=20, choices=TOKEN_STATUS, default='ACTIVE', db_index=True)
    
    # Limits
    max_purchases_per_user = models.IntegerField(default=1, help_text="Maximum times a user can buy this token")
    total_supply = models.IntegerField(null=True, blank=True, help_text="Total available tokens, null for unlimited")
    purchased_count = models.IntegerField(default=0, editable=False)
    
    # Metadata
    description = models.TextField(blank=True)
    icon = models.CharField(max_length=50, blank=True, help_text="FontAwesome or custom icon class")
    color = models.CharField(max_length=20, default='primary', help_text="Bootstrap color class")
    
    class Meta:
        ordering = ['token_number']
        indexes = [
            models.Index(fields=['status', 'token_number']),
        ]
    
    def save(self, *args, **kwargs):
        self.total_return = self.daily_return * self.return_days
        # Auto-deactivate tokens above 10
        if self.token_number > 10:
            self.status = 'INACTIVE'
        super().save(*args, **kwargs)
    
    def is_available(self):
        """Check if token is available for purchase"""
        if self.status != 'ACTIVE':
            return False
        if self.total_supply and self.purchased_count >= self.total_supply:
            return False
        return True
    
    def get_roi_percentage(self):
        """Calculate ROI percentage"""
        return (self.total_return / self.minimum_investment) * 100
    
    def __str__(self):
        return f"{self.name} - {self.daily_return} KSH/day for {self.return_days} days"


class Investment(TimeStampedModel):
    """
    User's investment in a token
    """
    INVESTMENT_STATUS = [
        ('ACTIVE', 'Active'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
        ('EXPIRED', 'Expired'),
    ]
    
    investment_id = models.CharField(max_length=50, unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='investments')
    token = models.ForeignKey(Token, on_delete=models.PROTECT, related_name='investments')
    
    # Investment details
    amount = models.DecimalField(max_digits=20, decimal_places=2, validators=[MinValueValidator(Decimal('800.00'))])
    daily_return = models.DecimalField(max_digits=10, decimal_places=2)
    
    # Dates
    start_date = models.DateTimeField(default=timezone.now)
    end_date = models.DateTimeField()
    last_payout_date = models.DateTimeField(null=True, blank=True)
    
    # Status
    status = models.CharField(max_length=20, choices=INVESTMENT_STATUS, default='ACTIVE', db_index=True)
    
    # Returns tracking
    total_paid = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))
    remaining_payouts = models.IntegerField()
    
    # Related transaction - FIXED: Added unique related_name
    transaction = models.OneToOneField(Transaction, on_delete=models.SET_NULL, null=True, blank=True, related_name='investment_purchase')
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['end_date', 'status']),
            models.Index(fields=['investment_id']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.pk:  # New investment
            # Check if token is still available
            if not self.token.is_available():
                raise ValidationError("This token is no longer available")
            
            self.daily_return = self.token.daily_return
            self.end_date = self.start_date + timezone.timedelta(days=self.token.return_days)
            self.remaining_payouts = self.token.return_days
            
            # Lock the funds in wallet
            wallet = self.user.wallet
            if wallet.available_balance() < self.amount:
                raise ValidationError("Insufficient balance")
            
            wallet.balance -= self.amount
            wallet.locked_balance += self.amount
            wallet.save()
            
            # Save investment first to get an ID
            super().save(*args, **kwargs)
            
            # Create transaction with the saved investment
            transaction = Transaction.objects.create(
                wallet=wallet,
                transaction_type='INVESTMENT',
                amount=self.amount,
                description=f"Investment in {self.token.name}",
                status='COMPLETED',
                investment=self  # Now self has an ID
            )
            
            # Update investment with transaction reference
            self.transaction = transaction
            super().save(update_fields=['transaction'])
            
            # Update token purchase count
            self.token.purchased_count += 1
            self.token.save()
            
        else:  # Existing investment
            super().save(*args, **kwargs)
    
    def process_daily_payout(self):
        """Process a single day's payout"""
        if self.status != 'ACTIVE':
            return False
        
        if self.remaining_payouts <= 0:
            self.complete_investment()
            return False
        
        # Calculate payout (can add tax here if needed)
        payout_amount = self.daily_return
        
        # Create profit transaction
        transaction = Transaction.objects.create(
            wallet=self.user.wallet,
            transaction_type='PROFIT',
            amount=payout_amount,
            description=f"Daily return from {self.token.name}",
            status='COMPLETED',
            investment=self  # This uses the related_name='transaction_entries'
        )
        
        # Update balances - FIXED: Use Decimal for calculations
        wallet = self.user.wallet
        wallet.balance += payout_amount
        wallet.total_earned += payout_amount
        
        # Gradually unlock - FIXED: Convert to Decimal properly
        daily_unlock = Decimal(str(float(self.amount) / self.token.return_days))
        wallet.locked_balance -= daily_unlock
        wallet.save()
        
        # Update investment
        self.total_paid += payout_amount
        self.remaining_payouts -= 1
        self.last_payout_date = timezone.now()
        
        if self.remaining_payouts <= 0:
            self.complete_investment()
        else:
            self.save()
        
        return True
    
    def complete_investment(self):
        """Mark investment as completed"""
        self.status = 'COMPLETED'
        
        # Unlock any remaining locked balance - FIXED: Proper Decimal calculation
        wallet = self.user.wallet
        remaining_unlock = Decimal(str(float(self.amount) * self.remaining_payouts / self.token.return_days))
        wallet.locked_balance -= remaining_unlock
        wallet.save()
        
        self.save()
    
    # ===== NEW METHOD ADDED FOR AUTO PAYOUT CHECKING =====
    def check_and_process_payout(self):
        """
        Check if 24 hours have passed and process payout if needed
        This can be called on every page load
        """
        from datetime import timedelta
        
        # Don't process if investment is not active
        if self.status != 'ACTIVE' or self.remaining_payouts <= 0:
            return False
        
        now = timezone.now()
        
        # Determine if payout is due
        if not self.last_payout_date:
            # First payout - check if 24 hours since creation
            if now >= self.created_at + timedelta(hours=24):
                return self.process_daily_payout()
        else:
            # Subsequent payouts - check if 24 hours since last payout
            if now >= self.last_payout_date + timedelta(hours=24):
                return self.process_daily_payout()
        
        return False
    # ====================================================
    
    def get_progress_percentage(self):
        """Calculate investment progress"""
        total_days = self.token.return_days
        completed_days = total_days - self.remaining_payouts
        return (completed_days / total_days) * 100
    
    def __str__(self):
        return f"{self.investment_id} - {self.user.username} - {self.token.name}"


# ==================== WITHDRAWAL SYSTEM ====================

class WithdrawalRequest(TimeStampedModel):
    """
    User withdrawal requests
    """
    WITHDRAWAL_STATUS = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('REJECTED', 'Rejected'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    PAYMENT_METHODS = [
        ('MPESA', 'M-Pesa'),
        ('BANK', 'Bank Transfer'),
    ]
    
    request_id = models.CharField(max_length=50, unique=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='withdrawals')
    
    # Amount
    amount = models.DecimalField(max_digits=20, decimal_places=2, validators=[MinValueValidator(Decimal('200.00'))])
    tax_amount = models.DecimalField(max_digits=20, decimal_places=2, default=Decimal('0.00'))
    net_amount = models.DecimalField(max_digits=20, decimal_places=2)
    
    # Payment details
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHODS, default='MPESA')
    phone_number = models.CharField(max_length=15, blank=True, null=True)  # For M-Pesa
    bank_details = models.JSONField(blank=True, null=True)  # Store bank account details as JSON
    
    # Status
    status = models.CharField(max_length=20, choices=WITHDRAWAL_STATUS, default='PENDING', db_index=True)
    
    # Processing
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='processed_withdrawals')
    processed_at = models.DateTimeField(null=True, blank=True)
    transaction_code = models.CharField(max_length=50, blank=True, null=True, help_text="M-Pesa or bank transaction code")
    
    # Rejection
    rejection_reason = models.TextField(blank=True, null=True)
    
    # Admin notes
    admin_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['request_id']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.pk:  
            # Calculate 5% tax
            self.tax_amount = self.amount * Decimal('0.05')
            self.net_amount = self.amount - self.tax_amount
            
            # Check minimum withdrawal
            if self.amount < 200:
                raise ValidationError("Minimum withdrawal amount is 200 KSH")
            
            # Check balance
            wallet = self.user.wallet
            if wallet.balance() < self.amount:
                raise ValidationError("Insufficient balance")
            
            # Lock the amount
            wallet.locked_balance += self.amount
            wallet.save()
        
        super().save(*args, **kwargs)
    
    def process(self, admin_user, transaction_code=None):
        """Approve and process withdrawal"""
        if self.status != 'PENDING':
            raise ValidationError("Can only process pending withdrawals")
        
        self.status = 'PROCESSING'
        self.processed_by = admin_user
        self.processed_at = timezone.now()
        self.transaction_code = transaction_code
        self.save()
    
    def complete(self, admin_user, transaction_code):
        """Mark withdrawal as completed"""
        if self.status not in ['PENDING', 'PROCESSING']:
            raise ValidationError("Can only complete pending or processing withdrawals")
        
        wallet = self.user.wallet
        
        # Create withdrawal transaction
        transaction = Transaction.objects.create(
            wallet=wallet,
            transaction_type='WITHDRAWAL',
            amount=self.amount,
            description=f"Withdrawal via {self.payment_method}",
            status='COMPLETED',
            withdrawal=self  # This uses the related_name='transaction_entries'
        )
        transaction.processed_by = admin_user
        transaction.processed_at = timezone.now()
        transaction.save()
        
        # Update wallet
        wallet.balance -= self.amount
        wallet.locked_balance -= self.amount
        wallet.total_withdrawn += self.amount
        wallet.save()
        
        # Add tax as separate transaction or record
        if self.tax_amount > 0:
            Transaction.objects.create(
                wallet=wallet,
                transaction_type='PENALTY',
                amount=self.tax_amount,
                description=f"5% withdrawal tax",
                status='COMPLETED'
            )
        
        self.status = 'COMPLETED'
        self.transaction_code = transaction_code
        self.save()
    
    def reject(self, admin_user, reason):
        """Reject withdrawal request"""
        if self.status not in ['PENDING', 'PROCESSING']:
            raise ValidationError("Can only reject pending or processing withdrawals")
        
        # Unlock the amount
        wallet = self.user.wallet
        wallet.locked_balance -= self.amount
        wallet.save()
        
        self.status = 'REJECTED'
        self.processed_by = admin_user
        self.processed_at = timezone.now()
        self.rejection_reason = reason
        self.save()
    
    def cancel(self):
        """User cancels withdrawal request"""
        if self.status != 'PENDING':
            raise ValidationError("Can only cancel pending withdrawals")
        
        # Unlock the amount
        wallet = self.user.wallet
        wallet.locked_balance -= self.amount
        wallet.save()
        
        self.status = 'CANCELLED'
        self.save()
    
    def __str__(self):
        return f"{self.request_id} - {self.user.username} - {self.amount} KSH"


# ==================== SYSTEM CONFIGURATION ====================

class SystemConfig(models.Model):
    """
    Global system configuration
    """
    key = models.CharField(max_length=50, unique=True, db_index=True)
    value = models.JSONField()
    description = models.TextField(blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "System Configuration"
        verbose_name_plural = "System Configurations"
    
    @classmethod
    def get_config(cls, key, default=None):
        """Get configuration value"""
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default
    
    def __str__(self):
        return self.key


class SystemLog(TimeStampedModel):
    """
    System-wide logging for important events
    """
    LOG_TYPES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
        ('ADMIN_ACTION', 'Admin Action'),
    ]
    
    log_type = models.CharField(max_length=20, choices=LOG_TYPES, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=100)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    data = models.JSONField(blank=True, null=True)  # Additional data
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['log_type', '-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]
    
    def __str__(self):
        return f"{self.log_type} - {self.action} - {self.created_at}"


# ==================== SIGNALS ====================

@receiver(post_save, sender=User)
def create_user_wallet_and_profile(sender, instance, created, **kwargs):
    """Create wallet and profile for new users"""
    if created:
        UserProfile.objects.get_or_create(user=instance)
        Wallet.objects.get_or_create(user=instance)
    else:
        # Ensure existing users have both
        UserProfile.objects.get_or_create(
            user=instance,
            defaults={
                'phone_number': '',
                'national_id_name': instance.get_full_name() or instance.username
            }
        )
        Wallet.objects.get_or_create(user=instance)


@receiver(post_save, sender=Investment)
def update_token_purchased_count(sender, instance, created, **kwargs):
    """Update token purchased count when investment is made"""
    if created:
        token = instance.token
        token.purchased_count = Investment.objects.filter(token=token, status='ACTIVE').count()
        token.save()


# ==================== ADMIN INTERFACE HELPERS ====================

class AdminDashboard:
    """Helper class for admin dashboard statistics"""
    
    @staticmethod
    def get_dashboard_stats():
        """Get comprehensive dashboard statistics"""
        from django.db.models import Sum, Count, Avg
        
        today = timezone.now().date()
        week_ago = today - timezone.timedelta(days=7)
        
        return {
            'users': {
                'total': User.objects.count(),
                'new_today': User.objects.filter(date_joined__date=today).count(),
                'new_week': User.objects.filter(date_joined__date__gte=week_ago).count(),
                'verified': UserProfile.objects.filter(phone_verified=True).count(),
            },
            'transactions': {
                'total_deposits': Transaction.objects.filter(
                    transaction_type='DEPOSIT', 
                    status='COMPLETED'
                ).aggregate(total=Sum('amount'))['total'] or 0,
                'total_withdrawals': Transaction.objects.filter(
                    transaction_type='WITHDRAWAL',
                    status='COMPLETED'
                ).aggregate(total=Sum('amount'))['total'] or 0,
                'pending_deposits': MpesaPayment.objects.filter(status='PENDING').count(),
                'pending_withdrawals': WithdrawalRequest.objects.filter(status='PENDING').count(),
            },
            'investments': {
                'active': Investment.objects.filter(status='ACTIVE').count(),
                'total_invested': Investment.objects.filter(
                    status='ACTIVE'
                ).aggregate(total=Sum('amount'))['total'] or 0,
                'total_paid_out': Investment.objects.aggregate(
                    total=Sum('total_paid')
                )['total'] or 0,
                'by_token': Token.objects.annotate(
                    active_count=Count('investments', filter=Q(investments__status='ACTIVE'))
                ).values('name', 'active_count'),
            },
            'referrals': {
                'total': UserProfile.objects.filter(referred_by__isnull=False).count(),
                'total_commission': Transaction.objects.filter(
                    transaction_type='REFERRAL_BONUS'
                ).aggregate(total=Sum('amount'))['total'] or 0,
            }
        }