If the database fails do this:

pip uninstall django

pip install "django>=4.2,<5.0"
 
Then run the migrations 

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'monero_db',       
        'USER': 'root',            
        'PASSWORD': '',            
        'HOST': '127.0.0.1',       
        'PORT': '3306',            
    }
}

cd BusinessApp
git pull origin main


# **Monero Investment Platform - Complete Documentation**


## **Project Overview**

Monero is a comprehensive Django-based investment platform that allows users to invest in tokenized assets, earn daily returns, and manage their portfolio through an intuitive interface. The platform features a robust admin dashboard, M-Pesa payment integration, referral system, and real-time investment tracking.

### **Purpose**
- Provide a secure platform for tokenized investments
- Automate daily profit distributions
- Enable seamless M-Pesa payments
- Track user investments and returns in real-time
- Offer comprehensive admin controls

### **Key Highlights**
- 🚀 **20+ Investment Tokens** with varying ROI
- 💰 **Automated Daily Payouts** via cron jobs
- 📱 **M-Pesa Integration** for Kenyan market
- 🔐 **KYC Verification** system
- 🤝 **Referral Program** with 5% commission
- 📊 **Real-time Dashboard** with analytics
- 👑 **Comprehensive Admin Panel**

---

## **Features**

### **User Features**
- ✅ User registration with referral tracking
- ✅ Email and phone verification
- ✅ KYC document upload (ID front/back, selfie)
- ✅ Wallet management (balance, locked funds)
- ✅ Deposit via M-Pesa
- ✅ Withdrawal requests (M-Pesa/Bank)
- ✅ Token investment purchases
- ✅ Daily profit tracking
- ✅ Transaction history
- ✅ Referral program with 5% commission
- ✅ Profile management
- ✅ Password change
- ✅ Real-time balance updates

### **Admin Features**
- ✅ Comprehensive dashboard with statistics
- ✅ Deposit verification
- ✅ Withdrawal processing
- ✅ User management (ban/unban)
- ✅ Token CRUD operations
- ✅ KYC verification
- ✅ System logs viewer
- ✅ Configuration management
- ✅ Balance adjustments
- ✅ Investment monitoring
- ✅ Transaction history viewer

### **Investment Features**
- ✅ 20 investment tokens (XMR-1 to XMR-20)
- ✅ Fixed daily returns
- ✅ Automated daily payouts
- ✅ Progress tracking
- ✅ Investment completion handling
- ✅ Max purchases per user limits
- ✅ Total supply management
- ✅ ROI percentage calculation

### **Security Features**
- ✅ CSRF protection
- ✅ XSS prevention
- ✅ SQL injection protection
- ✅ Rate limiting on login
- ✅ Session security
- ✅ Password complexity requirements
- ✅ Account lockout after failed attempts
- ✅ KYC verification
- ✅ Admin action logging
- ✅ IP address tracking

---

## **Technology Stack**

### **Backend**
| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.13+ | Core programming language |
| Django | 4.2.28 | Web framework |
| Django REST Framework | - | API endpoints |
| PostgreSQL/MySQL | - | Database |
| Celery | - | Async tasks (daily payouts) |
| Redis | - | Message broker |

### **Frontend**
| Technology | Version | Purpose |
|------------|---------|---------|
| HTML5 | - | Structure |
| CSS3 | - | Styling |
| Bootstrap | 5.3.2 | UI framework |
| JavaScript | ES6 | Interactivity |
| Chart.js | 4.4.0 | Data visualization |
| AOS | 2.3.1 | Animations |
| DataTables | 1.13.6 | Table management |

### **Payment Integration**
- M-Pesa API (Safaricom)
- STK Push integration
- Payment verification system

### **DevOps & Tools**
- Git (Version control)
- pip (Package management)
- Virtualenv (Isolation)
- Gunicorn (WSGI server)
- Nginx (Web server)
- Supervisor (Process management)

---

## **System Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                         Client Browser                       │
└───────────────────────────────┬─────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                      Django Application                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   URLs      │  │   Views     │  │   Models    │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Templates  │  │    Forms    │  │   Signals   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└───────────────────────────────┬─────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                         Database                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Users     │  │  Wallets    │  │Investments  │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Transactions│  │   Tokens    │  │    KYC      │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────┐
│                      External Services                       │
│  ┌─────────────────────┐  ┌─────────────────────┐          │
│  │     M-Pesa API      │  │    Email Service    │          │
│  └─────────────────────┘  └─────────────────────┘          │
│  ┌─────────────────────┐  ┌─────────────────────┐          │
│  │    SMS Gateway      │  │    Celery Beat      │          │
│  └─────────────────────┘  └─────────────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### **Data Flow**
1. **User Registration** → Profile created → Wallet created
2. **Deposit** → M-Pesa payment → Admin verification → Wallet updated
3. **Investment** → Wallet deduction → Investment created → Daily payouts start
4. **Withdrawal** → Request created → Admin processes → Funds sent
5. **Referral** → Referred user deposits → 5% bonus to referrer

---

## **Installation Guide**

### **Prerequisites**
- Python 3.13 or higher
- pip (Python package manager)
- virtualenv (recommended)
- MySQL/PostgreSQL database
- Git

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/yourusername/monero-investment.git
cd monero-investment
```

### **Step 2: Create Virtual Environment**
```bash
# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### **Step 3: Install Dependencies**
```bash
pip install -r requirements.txt
```

### **Step 4: Configure Database**
Create a MySQL/PostgreSQL database and update `Monero/settings.py`:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',  # or 'django.db.backends.postgresql'
        'NAME': 'monero_db',
        'USER': 'your_username',
        'PASSWORD': 'your_password',
        'HOST': 'localhost',
        'PORT': '3306',  # MySQL default
    }
}
```

### **Step 5: Environment Variables**
Create a `.env` file in the project root:

```env
DEBUG=True
SECRET_KEY=your-secret-key-here
DATABASE_NAME=monero_db
DATABASE_USER=root
DATABASE_PASSWORD=yourpassword
DATABASE_HOST=localhost
DATABASE_PORT=3306
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
MPESA_CONSUMER_KEY=your-mpesa-key
MPESA_CONSUMER_SECRET=your-mpesa-secret
MPESA_PASSKEY=your-mpesa-passkey
MPESA_SHORTCODE=174379
```

### **Step 6: Run Migrations**
```bash
python manage.py makemigrations
python manage.py migrate
```

### **Step 7: Create Superuser**
```bash
python manage.py createsuperuser
```

### **Step 8: Load Initial Data**
```bash
python manage.py shell
```

```python
from XMR.models import Token
from decimal import Decimal

# Create initial tokens
tokens = [
    {'name': 'XMR-1', 'display_name': 'Starter Pack', 'token_number': 1, 
     'minimum_investment': 800, 'daily_return': 40, 'return_days': 12},
    {'name': 'XMR-2', 'display_name': 'Growth Pack', 'token_number': 2,
     'minimum_investment': 1600, 'daily_return': 88, 'return_days': 12},
    {'name': 'XMR-3', 'display_name': 'Premium Pack', 'token_number': 3,
     'minimum_investment': 3200, 'daily_return': 192, 'return_days': 12},
    {'name': 'XMR-4', 'display_name': 'Elite Pack', 'token_number': 4,
     'minimum_investment': 6400, 'daily_return': 416, 'return_days': 12},
    {'name': 'XMR-5', 'display_name': 'Pro Pack', 'token_number': 5,
     'minimum_investment': 12800, 'daily_return': 896, 'return_days': 12},
]

for token_data in tokens:
    Token.objects.create(**token_data)
```

### **Step 9: Run Development Server**
```bash
python manage.py runserver
```

### **Step 10: Access the Application**
- User site: http://127.0.0.1:8000/
- Admin panel: http://127.0.0.1:8000/admin/

---

## **Configuration**

### **Settings Overview**

| Setting | Description | Default |
|---------|-------------|---------|
| `DEBUG` | Debug mode | True (dev), False (prod) |
| `SECRET_KEY` | Django secret key | Generate unique |
| `ALLOWED_HOSTS` | Allowed hostnames | ['localhost', '127.0.0.1'] |
| `DATABASES` | Database configuration | MySQL/PostgreSQL |
| `EMAIL_BACKEND` | Email backend | SMTP |
| `CELERY_BROKER_URL` | Celery broker | redis://localhost:6379 |
| `MPESA_*` | M-Pesa API keys | Your credentials |

### **System Configuration (Admin Panel)**
- **Minimum Deposit**: 800 KSH
- **Minimum Withdrawal**: 200 KSH
- **Withdrawal Tax**: 5%
- **Referral Commission**: 5%
- **M-Pesa Paybill**: 123456
- **M-Pesa Account**: INVEST
- **Site Name**: Monero Investments
- **Support Email**: support@example.com
- **Support Phone**: 0712345678

---

## **Database Schema**

### **Core Models**

#### **UserProfile**
| Field | Type | Description |
|-------|------|-------------|
| user | OneToOneField | Linked User |
| phone_number | CharField | User's phone |
| national_id_name | CharField | Name on ID |
| referral_code | CharField | Unique referral code |
| referred_by | ForeignKey | Referring user |
| phone_verified | Boolean | Phone verification status |
| id_verified | Boolean | ID verification status |
| is_banned | Boolean | Account banned status |
| ban_reason | TextField | Reason for ban |

#### **Wallet**
| Field | Type | Description |
|-------|------|-------------|
| user | OneToOneField | Linked User |
| balance | DecimalField | Current balance |
| locked_balance | DecimalField | Funds in investments |
| total_deposited | DecimalField | Lifetime deposits |
| total_withdrawn | DecimalField | Lifetime withdrawals |
| total_earned | DecimalField | Total profits earned |
| currency | CharField | Currency (KSH) |

#### **Transaction**
| Field | Type | Description |
|-------|------|-------------|
| transaction_id | CharField | Unique ID |
| wallet | ForeignKey | Linked wallet |
| transaction_type | CharField | Type (DEPOSIT, WITHDRAWAL, etc.) |
| amount | DecimalField | Transaction amount |
| status | CharField | PENDING/COMPLETED/FAILED |
| description | CharField | Transaction description |
| processed_by | ForeignKey | Admin who processed |
| processed_at | DateTimeField | Processing timestamp |

#### **Token**
| Field | Type | Description |
|-------|------|-------------|
| name | CharField | XMR-1, XMR-2, etc. |
| display_name | CharField | User-friendly name |
| token_number | IntegerField | 1-20 |
| minimum_investment | DecimalField | Min investment amount |
| daily_return | DecimalField | Daily return in KSH |
| return_days | IntegerField | Duration in days |
| total_return | DecimalField | Total return (calculated) |
| status | CharField | ACTIVE/INACTIVE/etc. |
| max_purchases_per_user | IntegerField | Purchase limit |
| total_supply | IntegerField | Token supply limit |
| purchased_count | IntegerField | Number sold |

#### **Investment**
| Field | Type | Description |
|-------|------|-------------|
| investment_id | CharField | Unique ID |
| user | ForeignKey | Investing user |
| token | ForeignKey | Token invested |
| amount | DecimalField | Investment amount |
| daily_return | DecimalField | Daily return rate |
| start_date | DateTimeField | Investment start |
| end_date | DateTimeField | Investment end |
| status | CharField | ACTIVE/COMPLETED |
| total_paid | DecimalField | Total paid out |
| remaining_payouts | IntegerField | Days remaining |

#### **WithdrawalRequest**
| Field | Type | Description |
|-------|------|-------------|
| request_id | CharField | Unique ID |
| user | ForeignKey | User requesting |
| amount | DecimalField | Request amount |
| tax_amount | DecimalField | 5% tax |
| net_amount | DecimalField | Amount after tax |
| payment_method | CharField | MPESA/BANK |
| status | CharField | PENDING/PROCESSING/COMPLETED |

### **Relationships Diagram**
```
User 1───1 UserProfile
User 1───1 Wallet
User 1───* MpesaPayment
User 1───* WithdrawalRequest
User 1───* Investment
Wallet 1───* Transaction
Token 1───* Investment
Transaction *───1 Investment (optional)
Transaction *───1 WithdrawalRequest (optional)
```

---

## **API Documentation**

### **Admin API Endpoints**

All admin API endpoints require staff privileges and CSRF token.

#### **Base URL**: `/admin-api/`

#### **Deposit Actions**

##### **Verify Deposit**
```javascript
POST /admin-api/
Content-Type: multipart/form-data

{
    "action": "verify_deposit",
    "deposit_id": 123
}

Response:
{
    "success": true,
    "message": "Deposit of 1000 KSH verified"
}
```

##### **Reject Deposit**
```javascript
POST /admin-api/
{
    "action": "reject_deposit",
    "deposit_id": 123,
    "reason": "Invalid transaction code"
}

Response:
{
    "success": true,
    "message": "Deposit rejected"
}
```

#### **Withdrawal Actions**

##### **Process Withdrawal**
```javascript
POST /admin-api/
{
    "action": "process_withdrawal",
    "withdrawal_id": 456
}

Response:
{
    "success": true,
    "message": "Withdrawal marked as processing"
}
```

##### **Complete Withdrawal**
```javascript
POST /admin-api/
{
    "action": "complete_withdrawal",
    "withdrawal_id": 456,
    "transaction_code": "MPESA123XYZ"
}

Response:
{
    "success": true,
    "message": "Withdrawal completed"
}
```

##### **Reject Withdrawal**
```javascript
POST /admin-api/
{
    "action": "reject_withdrawal",
    "withdrawal_id": 456,
    "reason": "Insufficient balance"
}

Response:
{
    "success": true,
    "message": "Withdrawal rejected"
}
```

#### **User Actions**

##### **Toggle User Ban**
```javascript
POST /admin-api/
{
    "action": "toggle_user_ban",
    "user_id": 789,
    "reason": "Fraudulent activity"
}

Response:
{
    "success": true,
    "is_banned": true,
    "message": "User banned"
}
```

##### **Adjust Balance**
```javascript
POST /admin-api/
{
    "action": "adjust_balance",
    "user_id": 789,
    "amount": 500.00,
    "description": "Bonus adjustment"
}

Response:
{
    "success": true,
    "new_balance": 2500.00,
    "message": "Added 500 KSH to wallet"
}
```

#### **Token Actions**

##### **Create Token**
```javascript
POST /admin-api/
{
    "action": "create_token",
    "name": "XMR-6",
    "display_name": "Ultimate Pack",
    "token_number": 6,
    "minimum_investment": 25600,
    "daily_return": 2048,
    "return_days": 12,
    "status": "ACTIVE",
    "max_purchases_per_user": 3
}

Response:
{
    "success": true,
    "message": "Token XMR-6 created successfully",
    "token_id": 10
}
```

##### **Update Token**
```javascript
POST /admin-api/
{
    "action": "update_token",
    "token_id": 10,
    "status": "INACTIVE",
    "daily_return": 2000
}

Response:
{
    "success": true,
    "message": "Token XMR-6 updated successfully"
}
```

#### **KYC Actions**

##### **Verify KYC**
```javascript
POST /admin-api/
{
    "action": "verify_kyc_all",
    "profile_id": 15
}

Response:
{
    "success": true,
    "message": "User fully verified"
}
```

### **User API Endpoints**

#### **Wallet Balance**
```javascript
GET /api/wallet/balance/

Response:
{
    "balance": 1500.00,
    "locked": 800.00,
    "available": 700.00
}
```

#### **Investment Statistics**
```javascript
GET /api/investment/stats/

Response:
{
    "active_count": 2,
    "completed_count": 1,
    "total_invested": 2400.00,
    "total_earned": 360.00,
    "next_payout": {
        "token": "XMR-1",
        "amount": 40.00,
        "days_left": 5,
        "end_date": "2024-03-15"
    }
}
```

---

## **User Guide**

### **Getting Started**

#### **1. Registration**
1. Navigate to the signup page
2. Enter your details:
   - Username (3-20 characters, letters/numbers/underscores)
   - Full name
   - Email address
   - Kenyan phone number (e.g., 0712345678)
   - Password (min 8 chars, with uppercase and number)
3. Optional: Enter referral code if you have one
4. Click "Sign Up"

#### **2. Email/Phone Verification**
- Check your email for verification link
- Phone verification occurs after first deposit

#### **3. Complete KYC (Optional)**
1. Go to Profile tab
2. Upload:
   - ID Front image
   - ID Back image
   - Selfie with ID
3. Admin will verify your documents

### **Making a Deposit**

1. Click "Deposit" in Quick Actions or go to Deposits tab
2. Follow M-Pesa instructions:
   ```
   Business No: 123456
   Account No: INVEST
   Amount: Minimum 800 KSH
   ```
3. Complete payment on your phone
4. Enter in the form:
   - Amount sent
   - Phone number used
   - M-Pesa confirmation message (optional)
   - Screenshot (optional)
5. Submit deposit request
6. Wait for admin verification (usually within 24 hours)

### **Investing in Tokens**

1. Go to Investments page
2. Browse available tokens
3. Check token details:
   - Minimum investment
   - Daily return
   - Duration
   - Total return
   - ROI percentage
4. Click "Invest Now" on your chosen token
5. Confirm the investment
6. Funds are deducted from your wallet
7. Daily payouts begin automatically

### **Tracking Your Investments**

- **Dashboard**: View summary of all investments
- **Investments Page**: 
  - Active investments with progress bars
  - Completed investment history
  - Total returns earned
  - Next payout countdown

### **Requesting Withdrawal**

1. Click "Withdraw" in Quick Actions
2. Enter amount (minimum 200 KSH)
3. Choose payment method:
   - **M-Pesa**: Enter phone number
   - **Bank Transfer**: Enter bank details
4. Review net amount after 5% tax
5. Submit request
6. Admin processes within 1-2 business days

### **Referral Program**

1. Get your referral link from Referrals tab
2. Share with friends
3. Earn 5% commission on their first deposit
4. Track referrals and earnings in Referrals tab

### **Profile Management**

- Update personal information
- Change password
- Upload KYC documents
- View verification status

---

## **Admin Guide**

### **Accessing Admin Panel**

1. Login with staff credentials
2. Navigate to `/admin/` or click admin link
3. Use the comprehensive dashboard

### **Dashboard Overview**

The dashboard shows:
- Total users and new registrations
- Total deposits, withdrawals, and profits
- Pending actions (deposits, withdrawals, KYC)
- Active investments and total invested
- Daily deposits chart
- Quick stats panel

### **Managing Deposits**

1. Go to Deposits tab
2. View all deposits filtered by status
3. For pending deposits:
   - Click ✅ to verify (adds funds to wallet)
   - Click ❌ to reject (with reason)
4. Verified deposits automatically:
   - Add funds to user's wallet
   - Create transaction record
   - Process referral bonus if first deposit

### **Processing Withdrawals**

1. Go to Withdrawals tab
2. View pending withdrawal requests
3. For each request:
   - Click ⚙️ to mark as "Processing"
   - Click ✅ to complete (after sending funds)
   - Click ❌ to reject (with reason)
4. Completed withdrawals:
   - Deduct funds from wallet
   - Apply 5% tax
   - Record transaction

### **User Management**

1. Go to Users tab
2. Search and filter users
3. View user details:
   - Personal information
   - Wallet balance
   - Verification status
4. Actions:
   - 👁️ View detailed information
   - 💰 Adjust balance (add/subtract funds)
   - 🔒 Ban/unban users (with reason)

### **Token Management**

1. Go to Tokens tab
2. View all tokens with details:
   - Token number, name, display name
   - Investment requirements
   - Returns and ROI
   - Availability status
3. Actions:
   - ✏️ Edit existing token
   - ➕ Create new token
   - 👁️ View token details

### **KYC Verification**

1. Go to KYC tab
2. View pending verification requests
3. Review uploaded documents:
   - ID front
   - ID back
   - Selfie with ID
4. Select verification options:
   - Phone verification
   - ID verification
5. Click "Verify Selected" or "Reject"

### **System Logs**

1. Go to Logs tab
2. View all system events:
   - User actions (login, registration)
   - Admin actions
   - System errors
   - Investment events
3. Filter by log type
4. Track IP addresses for security

### **Configuration Settings**

1. Go to Settings tab
2. Configure:
   - Deposit settings (min amount, M-Pesa details)
   - Withdrawal settings (min amount, tax rate)
   - Referral settings (commission rate)
   - Site information (name, contact)
3. Click "Save All Changes"

---

## **Investment System**

### **How Investments Work**

1. **Purchase**: User buys a token (e.g., XMR-1 for 800 KSH)
2. **Lock Period**: Funds are locked for the duration (e.g., 12 days)
3. **Daily Payouts**: Each day, user receives daily return (e.g., 40 KSH)
4. **Completion**: After duration ends, investment is marked "COMPLETED"
5. **Unlocking**: Locked funds are gradually released daily

### **Token Structure**

| Token | Investment | Daily Return | Duration | Total Return | ROI |
|-------|------------|--------------|----------|--------------|-----|
| XMR-1 | 800 KSH | 40 KSH | 12 days | 480 KSH | 60% |
| XMR-2 | 1,600 KSH | 88 KSH | 12 days | 1,056 KSH | 66% |
| XMR-3 | 3,200 KSH | 192 KSH | 12 days | 2,304 KSH | 72% |
| XMR-4 | 6,400 KSH | 416 KSH | 12 days | 4,992 KSH | 78% |
| XMR-5 | 12,800 KSH | 896 KSH | 12 days | 10,752 KSH | 84% |
| XMR-6 | 25,600 KSH | 2,048 KSH | 12 days | 24,576 KSH | 96% |
| XMR-7 | 51,200 KSH | 4,608 KSH | 12 days | 55,296 KSH | 108% |
| XMR-8 | 102,400 KSH | 10,240 KSH | 12 days | 122,880 KSH | 120% |

### **Daily Payout Process**

```python
# Automated cron job runs daily
def process_daily_payouts():
    active_investments = Investment.objects.filter(status='ACTIVE')
    
    for investment in active_investments:
        # Calculate daily payout
        payout = investment.daily_return
        
        # Create profit transaction
        Transaction.objects.create(
            wallet=investment.user.wallet,
            transaction_type='PROFIT',
            amount=payout,
            investment=investment
        )
        
        # Update wallet
        wallet.balance += payout
        wallet.total_earned += payout
        wallet.locked_balance -= (investment.amount / investment.token.return_days)
        
        # Update investment
        investment.total_paid += payout
        investment.remaining_payouts -= 1
        
        if investment.remaining_payouts <= 0:
            investment.status = 'COMPLETED'
```

### **Investment Status Flow**
```
PURCHASED → ACTIVE → (daily payouts) → COMPLETED
               ↓
            CANCELLED (rare)
```

---

## **Payment Integration**

### **M-Pesa Integration**

#### **Payment Flow**
1. User initiates deposit
2. User sends money via M-Pesa Paybill
3. User submits transaction details
4. Admin verifies payment
5. Wallet credited automatically

#### **Message Parsing**
The system automatically extracts from M-Pesa messages:
- Transaction code (e.g., `ABC123XYZ`)
- Amount sent
- Sender phone number
- Transaction date

#### **Verification Process**
```python
def verify(self, admin_user):
    # Update status
    self.status = 'VERIFIED'
    self.verified_by = admin_user
    self.verified_at = timezone.now()
    
    # Create deposit transaction
    transaction = Transaction.objects.create(
        wallet=self.user.wallet,
        transaction_type='DEPOSIT',
        amount=self.amount,
        status='COMPLETED'
    )
    
    # Update wallet
    wallet = self.user.wallet
    wallet.balance += self.amount
    wallet.total_deposited += self.amount
    
    # Process referral bonus on first deposit
    if wallet.total_deposited == self.amount:
        self.process_referral_bonus()
```

### **Withdrawal Processing**

#### **Tax Calculation**
- 5% tax on all withdrawals
- Tax recorded as separate transaction
- Net amount sent to user

#### **Payment Methods**
1. **M-Pesa**: Instant mobile money transfer
2. **Bank Transfer**: 1-2 business days

---

## **Security Features**

### **Authentication Security**
- Password complexity requirements (min 8 chars, uppercase, number)
- Rate limiting on login attempts (5 attempts per minute)
- Session timeout after 30 minutes of inactivity
- CSRF protection on all forms
- Secure password hashing (PBKDF2)

### **Data Security**
- All sensitive data encrypted at rest
- HTTPS enforcement in production
- SQL injection prevention via Django ORM
- XSS protection via template escaping
- Clickjacking protection via X-Frame-Options

### **Financial Security**
- Atomic transactions for all financial operations
- Row-level locking to prevent race conditions
- Audit trail via SystemLog
- Admin action logging
- Balance reconciliation tools

### **User Security**
- Email verification required
- Phone verification for withdrawals
- KYC verification for large transactions
- Account lockout after failed login attempts
- IP tracking for suspicious activity

### **Admin Security**
- Two-factor authentication option
- IP whitelisting for admin access
- Session management
- Admin action logging
- Role-based access control

---

## **Testing**

### **Running Tests**
```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test XMR.tests

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

### **Test Categories**

#### **Model Tests**
```python
def test_wallet_creation():
    user = User.objects.create_user(username='test', password='test123')
    wallet = Wallet.objects.get(user=user)
    assert wallet.balance == 0
    assert wallet.locked_balance == 0
```

#### **View Tests**
```python
def test_investment_purchase():
    client.login(username='test', password='test123')
    response = client.post('/investment/1/buy/')
    assert response.status_code == 302
    assert Investment.objects.count() == 1
```

#### **API Tests**
```python
def test_admin_api():
    admin_client.login(username='admin', password='admin123')
    response = admin_client.post('/admin-api/', {
        'action': 'verify_deposit',
        'deposit_id': 1
    })
    assert response.json()['success'] == True
```

### **Test Data Setup**
```python
# fixtures/test_data.json
{
    "model": "XMR.token",
    "pk": 1,
    "fields": {
        "name": "XMR-1",
        "minimum_investment": "800.00",
        "daily_return": "40.00",
        "return_days": 12
    }
}
```

---

## **Deployment**

### **Production Requirements**

#### **Server Requirements**
- Ubuntu 20.04 LTS or higher
- Python 3.13+
- Nginx
- MySQL/PostgreSQL
- Redis
- Supervisor
- SSL Certificate

#### **Environment Variables**
```bash
# .env.production
DEBUG=False
SECRET_KEY=your-very-secure-secret-key
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DATABASE_NAME=monero_prod
DATABASE_USER=monero_user
DATABASE_PASSWORD=strong_password
DATABASE_HOST=localhost
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=noreply@yourdomain.com
EMAIL_HOST_PASSWORD=email_password
MPESA_CONSUMER_KEY=your_mpesa_key
MPESA_CONSUMER_SECRET=your_mpesa_secret
```

### **Deployment Steps**

#### **1. Server Setup**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install python3-pip python3-dev libpq-dev nginx redis-server -y
sudo apt install mysql-server  # or postgresql

# Create project directory
sudo mkdir -p /var/www/monero
sudo chown -R $USER:$USER /var/www/monero
```

#### **2. Clone & Setup Project**
```bash
cd /var/www/monero
git clone https://github.com/yourusername/monero-investment.git .
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install gunicorn
```

#### **3. Configure Database**
```bash
# MySQL
sudo mysql
CREATE DATABASE monero_prod CHARACTER SET utf8mb4;
CREATE USER 'monero_user'@'localhost' IDENTIFIED BY 'strong_password';
GRANT ALL PRIVILEGES ON monero_prod.* TO 'monero_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

#### **4. Collect Static Files**
```bash
python manage.py collectstatic
```

#### **5. Configure Gunicorn**
```bash
# Create gunicorn service
sudo nano /etc/systemd/system/gunicorn.service
```

```ini
[Unit]
Description=gunicorn daemon
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/var/www/monero
ExecStart=/var/www/monero/venv/bin/gunicorn --workers 3 --bind unix:/var/www/monero/monero.sock Monero.wsgi:application

[Install]
WantedBy=multi-user.target
```

#### **6. Configure Nginx**
```bash
sudo nano /etc/nginx/sites-available/monero
```

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    location = /favicon.ico { access_log off; log_not_found off; }
    
    location /static/ {
        root /var/www/monero;
    }
    
    location /media/ {
        root /var/www/monero;
    }
    
    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/monero/monero.sock;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/monero /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

#### **7. Configure SSL with Let's Encrypt**
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

#### **8. Configure Celery**
```bash
sudo nano /etc/supervisor/conf.d/celery.conf
```

```ini
[program:celery]
command=/var/www/monero/venv/bin/celery -A Monero worker --loglevel=info
directory=/var/www/monero
user=www-data
numprocs=1
stdout_logfile=/var/log/celery.log
stderr_logfile=/var/log/celery.log
autostart=true
autorestart=true
startsecs=10

[program:celery-beat]
command=/var/www/monero/venv/bin/celery -A Monero beat --loglevel=info
directory=/var/www/monero
user=www-data
numprocs=1
stdout_logfile=/var/log/celery-beat.log
stderr_logfile=/var/log/celery-beat.log
autostart=true
autorestart=true
startsecs=10
```

```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start all
```

#### **9. Set up Daily Payout Cron Job**
```bash
crontab -e
```

```cron
# Run daily payouts at 00:01 every day
1 0 * * * cd /var/www/monero && /var/www/monero/venv/bin/python manage.py shell -c "from XMR.views import process_daily_payouts; process_daily_payouts()"

# Check for expired investments at 00:30 every day
30 0 * * * cd /var/www/monero && /var/www/monero/venv/bin/python manage.py shell -c "from XMR.views import check_expired_investments; check_expired_investments()"
```

#### **10. Restart Services**
```bash
sudo systemctl restart gunicorn
sudo systemctl restart nginx
sudo supervisorctl restart all
```

---

## **Troubleshooting**

### **Common Issues & Solutions**

#### **1. "NoReverseMatch" Error**
**Problem**: URL reverse lookup fails
**Solution**: 
- Check URL names in `urls.py`
- Use correct namespace: `'XMR:view_name'`
- Don't use fragments in redirects

#### **2. "Cannot filter a query once a slice has been taken"**
**Problem**: Filtering after slicing a queryset
**Solution**:
```python
# Wrong
all_investments = Investment.objects.all()[:20]
active = all_investments.filter(status='ACTIVE')  # ERROR

# Correct
active = Investment.objects.filter(status='ACTIVE')[:20]
```

#### **3. Investment Creation Fails with "Insufficient Balance"**
**Problem**: Wallet shows balance but investment fails
**Solution**:
```python
# Check available balance
available = wallet.balance - wallet.locked_balance
print(f"Balance: {wallet.balance}, Locked: {wallet.locked_balance}, Available: {available}")

# Fix locked balance if incorrect
wallet.locked_balance = 0
wallet.save()
```

#### **4. M-Pesa Payment Not Showing**
**Problem**: Deposits not appearing in admin
**Solution**:
- Check if `deposits_data` is in context
- Verify M-Pesa payment was created
- Check database for entries

#### **5. Daily Payouts Not Running**
**Problem**: Users not receiving daily returns
**Solution**:
```bash
# Test manually
python manage.py shell -c "from XMR.views import process_daily_payouts; process_daily_payouts()"

# Check cron job
crontab -l

# Check logs
tail -f /var/log/syslog | grep CRON
```

#### **6. Database Connection Issues**
**Problem**: "Can't connect to MySQL server"
**Solution**:
```bash
# Check MySQL status
sudo systemctl status mysql

# Restart MySQL
sudo systemctl restart mysql

# Check credentials in settings.py
```

#### **7. Static Files Not Loading**
**Problem**: CSS/JS files 404
**Solution**:
```bash
python manage.py collectstatic --noinput
sudo systemctl restart nginx
```

#### **8. Email Not Sending**
**Problem**: Registration emails not sent
**Solution**:
- Check email settings in `.env`
- Verify Gmail App Password
- Check spam folder
- Test with console backend first

### **Debugging Tips**

#### **Enable Debug Logging**
```python
# settings.py
LOGGING = {
    'version': 1,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'XMR': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

#### **Check Database Queries**
```python
from django.db import connection
print(connection.queries)
```

#### **Test API Endpoints**
```bash
curl -X POST http://localhost:8000/admin-api/ \
  -H "X-CSRFToken: your-csrf-token" \
  -d "action=verify_deposit&deposit_id=1"
```

---

## **Contributing**

### **Getting Started**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Submit a pull request

### **Development Guidelines**

#### **Code Style**
- Follow PEP 8
- Use meaningful variable names
- Add docstrings to functions
- Comment complex logic

#### **Git Commit Messages**
```
feat: Add new investment token
fix: Resolve withdrawal redirect error
docs: Update README with deployment steps
style: Format CSS for better readability
refactor: Optimize database queries
test: Add unit tests for wallet model
```

#### **Pull Request Process**
1. Update documentation
2. Add tests for new features
3. Ensure all tests pass
4. Get review from maintainers
5. Merge after approval

### **Project Structure**
```
monero/
├── manage.py
├── Monero/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── XMR/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── forms.py
│   ├── templatetags/
│   │   ├── __init__.py
│   │   └── custom_filters.py
│   ├── migrations/
│   ├── templates/
│   │   └── XMR/
│   │       ├── index.html
│   │       ├── account.html
│   │       ├── investments.html
│   │       ├── signupin.html
│   │       └── admin.html
│   └── static/
│       └── XMR/
│           ├── css/
│           └── js/
├── requirements.txt
├── README.md
└── .env
```

---

## **License**

This project is licensed under the MIT License.

### **MIT License**

```
MIT License

Copyright (c) 2024 Monero Investments

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## **Support**

### **Contact Information**
- **Email**: support@moneroinvest.com
- **Phone**: +254 712 345 678
- **Website**: https://moneroinvest.com

### **Documentation**
- **API Docs**: `/api/docs/`
- **Admin Guide**: `/admin/help/`
- **User Guide**: `/help/`

### **Reporting Issues**
- GitHub Issues: https://github.com/WanjalaDavis/BusinessApp/issues
- Security issues: security@moneroinvest.com

---

## **Version History**

### **v1.0.0** (Initial Release)
- Basic user authentication
- Wallet system
- Token investments
- M-Pesa integration
- Admin dashboard

### **v1.1.0** (Current)
- Fixed investment creation bug
- Added transaction history
- Improved error handling
- Enhanced admin panel
- Added investment recovery tool

### **v1.2.0** (Planned)
- Mobile app integration
- Automated KYC verification
- Multiple currency support
- Investment reinvestment feature
- Real-time notifications

---

## **Acknowledgments**

- Django Team for the amazing framework
- Bootstrap for the UI components
- Safaricom for M-Pesa API
- All contributors and testers
- Our amazing community of users

---

**© 2026 Monero Investments. All rights reserved.**