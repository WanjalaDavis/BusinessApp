// admin.js - Complete admin functionality for Monero Investment Platform

// ==================== GLOBAL CONFIGURATION ====================
const API_URL = '/admin/api/';
let currentKycId = null;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin panel initialized');
    initializeEventListeners();
    initializeTooltips();
    setupAutoRefresh();
});

function initializeEventListeners() {
    // Filter change listeners
    document.getElementById('depositStatusFilter')?.addEventListener('change', function() {
        window.location.href = updateQueryStringParameter(window.location.href, 'deposit_status', this.value);
    });
    
    document.getElementById('withdrawalStatusFilter')?.addEventListener('change', function() {
        window.location.href = updateQueryStringParameter(window.location.href, 'withdrawal_status', this.value);
    });
    
    // Search with debounce
    const userSearch = document.getElementById('userSearch');
    if (userSearch) {
        userSearch.addEventListener('keyup', debounce(function() {
            filterUsers();
        }, 500));
    }
    
    // Modal forms
    document.getElementById('adjustBalanceForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        submitBalanceAdjustment();
    });
    
    document.getElementById('tokenForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        createToken();
    });
    
    document.getElementById('settingsForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        saveSettings(e);
    });
    
    // Tab change handler for URL hash
    const tabs = document.querySelectorAll('[data-bs-toggle="tab"]');
    tabs.forEach(tab => {
        tab.addEventListener('shown.bs.tab', function(e) {
            history.pushState(null, null, e.target.getAttribute('data-bs-target'));
        });
    });
}

function initializeTooltips() {
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => {
        new bootstrap.Tooltip(tooltip);
    });
}

function setupAutoRefresh() {
    // Auto-refresh data every 30 seconds for pending items
    setInterval(function() {
        if (document.visibilityState === 'visible') {
            refreshPendingCounts();
        }
    }, 30000);
}

// ==================== HELPER FUNCTIONS ====================

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function updateQueryStringParameter(uri, key, value) {
    const re = new RegExp("([?&])" + key + "=.*?(&|$)", "i");
    const separator = uri.indexOf('?') !== -1 ? "&" : "?";
    if (uri.match(re)) {
        return uri.replace(re, '$1' + key + "=" + value + '$2');
    } else {
        return uri + separator + key + "=" + value;
    }
}

function showNotification(message, type = 'success') {
    const toastContainer = document.getElementById('toastContainer') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="bi bi-${type === 'success' ? 'check-circle' : 'exclamation-circle'} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast, { delay: 3000 });
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999;';
    document.body.appendChild(container);
    return container;
}

function showConfirmDialog(title, message, onConfirm) {
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content rounded-4">
                <div class="modal-header border-0">
                    <h5 class="modal-title fw-semibold">${title}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <p>${message}</p>
                </div>
                <div class="modal-footer border-0">
                    <button type="button" class="btn btn-light rounded-3" data-bs-dismiss="modal">Cancel</button>
                    <button type="button" class="btn btn-danger rounded-3" id="confirmActionBtn">Confirm</button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
    
    document.getElementById('confirmActionBtn').addEventListener('click', function() {
        bsModal.hide();
        onConfirm();
        setTimeout(() => modal.remove(), 300);
    });
    
    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

// ==================== API CALLS ====================

async function apiCall(action, data = {}) {
    const formData = new FormData();
    formData.append('action', action);
    formData.append('csrfmiddlewaretoken', getCsrfToken());
    
    for (const [key, value] of Object.entries(data)) {
        formData.append(key, value);
    }
    
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'API call failed');
        }
        
        return result;
    } catch (error) {
        console.error('API Error:', error);
        showNotification(error.message, 'danger');
        throw error;
    }
}

function getCsrfToken() {
    return document.querySelector('[name=csrfmiddlewaretoken]')?.value || '';
}

// ==================== DEPOSIT ACTIONS ====================

async function verifyDeposit(depositId) {
    try {
        const result = await apiCall('verify_deposit', { deposit_id: depositId });
        
        if (result.success) {
            showNotification(result.message, 'success');
            
            // Update UI
            const row = document.getElementById(`deposit-${depositId}`);
            if (row) {
                const statusCell = row.querySelector('td:nth-child(7)');
                statusCell.innerHTML = '<span class="badge bg-success">Verified</span>';
                
                // Remove action buttons
                const actionsCell = row.querySelector('td:last-child');
                actionsCell.innerHTML = '';
            }
            
            // Update pending counts
            refreshPendingCounts();
        }
    } catch (error) {
        // Error already shown by apiCall
    }
}

async function rejectDeposit(depositId) {
    showConfirmDialog('Reject Deposit', 'Are you sure you want to reject this deposit?', async () => {
        const reason = prompt('Please provide a reason for rejection:', 'Incorrect payment details');
        if (reason === null) return;
        
        try {
            const result = await apiCall('reject_deposit', { 
                deposit_id: depositId,
                reason: reason 
            });
            
            if (result.success) {
                showNotification(result.message, 'warning');
                
                // Update UI
                const row = document.getElementById(`deposit-${depositId}`);
                if (row) {
                    const statusCell = row.querySelector('td:nth-child(7)');
                    statusCell.innerHTML = '<span class="badge bg-danger">Rejected</span>';
                    
                    // Remove action buttons
                    const actionsCell = row.querySelector('td:last-child');
                    actionsCell.innerHTML = '';
                }
                
                // Update pending counts
                refreshPendingCounts();
            }
        } catch (error) {}
    });
}

function viewScreenshot(depositId) {
    // This would typically open a modal with the screenshot
    // For now, we'll just log it
    console.log('View screenshot for deposit:', depositId);
    showNotification('Screenshot viewing coming soon', 'info');
}

// ==================== WITHDRAWAL ACTIONS ====================

async function processWithdrawal(withdrawalId) {
    try {
        const result = await apiCall('process_withdrawal', { withdrawal_id: withdrawalId });
        
        if (result.success) {
            showNotification(result.message, 'info');
            
            // Update UI
            const row = document.getElementById(`withdrawal-${withdrawalId}`);
            if (row) {
                const statusCell = row.querySelector('td:nth-child(9)');
                statusCell.innerHTML = '<span class="badge bg-info">Processing</span>';
                
                // Update actions
                const actionsCell = row.querySelector('td:last-child');
                actionsCell.innerHTML = `
                    <button class="btn btn-sm btn-success" onclick="completeWithdrawal(${withdrawalId})">
                        <i class="bi bi-check-lg"></i> Complete
                    </button>
                `;
            }
        }
    } catch (error) {}
}

async function completeWithdrawal(withdrawalId) {
    const transactionCode = prompt('Enter transaction code (M-Pesa/Bank):');
    if (!transactionCode) return;
    
    try {
        const result = await apiCall('complete_withdrawal', { 
            withdrawal_id: withdrawalId,
            transaction_code: transactionCode 
        });
        
        if (result.success) {
            showNotification(result.message, 'success');
            
            // Update UI
            const row = document.getElementById(`withdrawal-${withdrawalId}`);
            if (row) {
                const statusCell = row.querySelector('td:nth-child(9)');
                statusCell.innerHTML = '<span class="badge bg-success">Completed</span>';
                
                // Remove action buttons
                const actionsCell = row.querySelector('td:last-child');
                actionsCell.innerHTML = '';
            }
            
            // Update pending counts
            refreshPendingCounts();
        }
    } catch (error) {}
}

async function rejectWithdrawal(withdrawalId) {
    showConfirmDialog('Reject Withdrawal', 'Are you sure you want to reject this withdrawal?', async () => {
        const reason = prompt('Please provide a reason for rejection:', 'Insufficient funds');
        if (reason === null) return;
        
        try {
            const result = await apiCall('reject_withdrawal', { 
                withdrawal_id: withdrawalId,
                reason: reason 
            });
            
            if (result.success) {
                showNotification(result.message, 'warning');
                
                // Update UI
                const row = document.getElementById(`withdrawal-${withdrawalId}`);
                if (row) {
                    const statusCell = row.querySelector('td:nth-child(9)');
                    statusCell.innerHTML = '<span class="badge bg-danger">Rejected</span>';
                    
                    // Remove action buttons
                    const actionsCell = row.querySelector('td:last-child');
                    actionsCell.innerHTML = '';
                }
                
                // Update pending counts
                refreshPendingCounts();
            }
        } catch (error) {}
    });
}

// ==================== USER ACTIONS ====================

async function showUserDetails(userId) {
    try {
        // You might want to fetch user details via API here
        // For now, we'll show a modal with basic info
        const modal = new bootstrap.Modal(document.getElementById('userDetailsModal'));
        
        // Find user in the table data
        const userRow = document.getElementById(`user-${userId}`);
        if (userRow) {
            const cells = userRow.querySelectorAll('td');
            const content = document.getElementById('userDetailsContent');
            
            content.innerHTML = `
                <div class="text-center mb-4">
                    <div class="bg-warning bg-opacity-10 p-4 rounded-4 d-inline-block">
                        <i class="bi bi-person-circle fs-1" style="color: #f15a24;"></i>
                    </div>
                    <h4 class="mt-3">${cells[1]?.innerText || 'User'}</h4>
                </div>
                <div class="row g-3">
                    <div class="col-6">
                        <div class="bg-light p-3 rounded-3">
                            <small class="text-muted">Full Name</small>
                            <div class="fw-bold">${cells[2]?.innerText || '—'}</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="bg-light p-3 rounded-3">
                            <small class="text-muted">Email</small>
                            <div class="fw-bold">${cells[3]?.innerText || '—'}</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="bg-light p-3 rounded-3">
                            <small class="text-muted">Phone</small>
                            <div class="fw-bold">${cells[4]?.innerText || '—'}</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="bg-light p-3 rounded-3">
                            <small class="text-muted">Balance</small>
                            <div class="fw-bold">${cells[5]?.innerText || '0 KSH'}</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="bg-light p-3 rounded-3">
                            <small class="text-muted">Referral Code</small>
                            <div class="fw-bold"><code>${cells[6]?.innerText || '—'}</code></div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="bg-light p-3 rounded-3">
                            <small class="text-muted">Joined</small>
                            <div class="fw-bold">${cells[9]?.innerText || '—'}</div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        modal.show();
    } catch (error) {
        console.error('Error showing user details:', error);
    }
}

async function toggleUserBan(userId, shouldBan) {
    const action = shouldBan ? 'ban' : 'unban';
    showConfirmDialog(
        `${shouldBan ? 'Ban' : 'Unban'} User`, 
        `Are you sure you want to ${action} this user?`,
        async () => {
            const reason = shouldBan ? prompt('Please provide a reason for banning:') : '';
            if (shouldBan && reason === null) return;
            
            try {
                const result = await apiCall('toggle_user_ban', { 
                    user_id: userId,
                    reason: reason || ''
                });
                
                if (result.success) {
                    showNotification(result.message, 'success');
                    
                    // Update UI
                    const row = document.getElementById(`user-${userId}`);
                    if (row) {
                        const statusCell = row.querySelector('td:nth-child(9)');
                        const actionsCell = row.querySelector('td:last-child');
                        
                        if (result.is_banned) {
                            statusCell.innerHTML = '<span class="badge bg-danger">Banned</span>';
                            actionsCell.innerHTML = `
                                <button class="btn btn-sm btn-outline-primary" onclick="showUserDetails(${userId})">
                                    <i class="bi bi-eye"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-warning" onclick="adjustBalance(${userId})">
                                    <i class="bi bi-cash"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-success" onclick="toggleUserBan(${userId}, false)">
                                    <i class="bi bi-unlock"></i>
                                </button>
                            `;
                        } else {
                            statusCell.innerHTML = '<span class="badge bg-success">Active</span>';
                            actionsCell.innerHTML = `
                                <button class="btn btn-sm btn-outline-primary" onclick="showUserDetails(${userId})">
                                    <i class="bi bi-eye"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-warning" onclick="adjustBalance(${userId})">
                                    <i class="bi bi-cash"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger" onclick="toggleUserBan(${userId}, true)">
                                    <i class="bi bi-lock"></i>
                                </button>
                            `;
                        }
                    }
                }
            } catch (error) {}
        }
    );
}

async function adjustBalance(userId) {
    document.getElementById('adjustUserId').value = userId;
    const modal = new bootstrap.Modal(document.getElementById('adjustBalanceModal'));
    modal.show();
}

async function submitBalanceAdjustment() {
    const form = document.getElementById('adjustBalanceForm');
    const formData = new FormData(form);
    const userId = formData.get('user_id');
    const amount = formData.get('amount');
    const description = formData.get('description');
    
    try {
        const result = await apiCall('adjust_balance', {
            user_id: userId,
            amount: amount,
            description: description
        });
        
        if (result.success) {
            showNotification(result.message, 'success');
            
            // Update user balance in table
            const row = document.getElementById(`user-${userId}`);
            if (row) {
                const balanceCell = row.querySelector('td:nth-child(6)');
                balanceCell.innerHTML = `<strong>${result.new_balance.toFixed(2)} KSH</strong>`;
            }
            
            // Close modal
            bootstrap.Modal.getInstance(document.getElementById('adjustBalanceModal')).hide();
            form.reset();
        }
    } catch (error) {}
}

// ==================== TOKEN ACTIONS ====================

async function createToken() {
    const form = document.getElementById('tokenForm');
    const formData = new FormData(form);
    const data = {};
    
    for (const [key, value] of formData.entries()) {
        data[key] = value;
    }
    
    try {
        const result = await apiCall('create_token', data);
        
        if (result.success) {
            showNotification(result.message, 'success');
            
            // Close modal and refresh page to show new token
            bootstrap.Modal.getInstance(document.getElementById('tokenModal')).hide();
            form.reset();
            
            // Reload page after short delay
            setTimeout(() => window.location.reload(), 1000);
        }
    } catch (error) {}
}

async function editToken(tokenId) {
    // For now, just show notification
    showNotification('Edit functionality coming soon', 'info');
}

// ==================== KYC ACTIONS ====================

async function verifyKyc(kycId, type) {
    let action;
    let message;
    
    if (type === 'all') {
        action = 'verify_kyc_all';
        message = 'User fully verified';
    } else if (type === 'phone') {
        action = 'verify_kyc_phone';
        message = 'Phone verified';
    } else {
        action = 'verify_kyc_id';
        message = 'ID verified';
    }
    
    try {
        const result = await apiCall(action, { profile_id: kycId });
        
        if (result.success) {
            showNotification(result.message || message, 'success');
            
            // Remove KYC card or update UI
            const card = document.querySelector(`[onclick*="openKycModal(${kycId})"]`)?.closest('.col-md-6');
            if (card) {
                card.remove();
            }
            
            // Update pending counts
            refreshPendingCounts();
        }
    } catch (error) {}
}

function openKycModal(kycId) {
    currentKycId = kycId;
    
    // Find KYC data in the cards
    const card = document.querySelector(`[onclick*="openKycModal(${kycId})"]`)?.closest('.col-md-6');
    if (card) {
        const content = document.getElementById('verificationModalContent');
        const username = card.querySelector('h6')?.innerText || 'User';
        const fullName = card.querySelector('.small.text-muted')?.innerHTML?.split('<br>')[0]?.replace('<i class="bi bi-person me-2"></i>', '') || '';
        const phone = card.querySelector('.small.text-muted')?.innerHTML?.split('<br>')[1]?.replace('<i class="bi bi-phone me-2"></i>', '') || '';
        
        content.innerHTML = `
            <div class="text-center mb-4">
                <h5>${username}</h5>
                <p class="text-muted">${fullName}</p>
            </div>
            <div class="row g-3">
                <div class="col-4">
                    <div class="bg-light p-2 rounded-3 text-center">
                        <small class="text-muted d-block">Phone</small>
                        <strong>${phone}</strong>
                    </div>
                </div>
                <div class="col-4">
                    <div class="bg-light p-2 rounded-3 text-center">
                        <small class="text-muted d-block">Status</small>
                        <span class="badge bg-warning">Pending</span>
                    </div>
                </div>
                <div class="col-4">
                    <div class="bg-light p-2 rounded-3 text-center">
                        <small class="text-muted d-block">Documents</small>
                        <strong>3/3</strong>
                    </div>
                </div>
            </div>
            <div class="row g-3 mt-2">
                <div class="col-4">
                    <button class="btn btn-sm btn-outline-info w-100" onclick="viewKycDocument('id_front')">
                        <i class="bi bi-card-image"></i> Front ID
                    </button>
                </div>
                <div class="col-4">
                    <button class="btn btn-sm btn-outline-info w-100" onclick="viewKycDocument('id_back')">
                        <i class="bi bi-card-image"></i> Back ID
                    </button>
                </div>
                <div class="col-4">
                    <button class="btn btn-sm btn-outline-info w-100" onclick="viewKycDocument('selfie')">
                        <i class="bi bi-person-badge"></i> Selfie
                    </button>
                </div>
            </div>
        `;
    }
    
    const modal = new bootstrap.Modal(document.getElementById('verificationModal'));
    modal.show();
}

function verifyKycFromModal() {
    if (currentKycId) {
        verifyKyc(currentKycId, 'all');
        bootstrap.Modal.getInstance(document.getElementById('verificationModal')).hide();
    }
}

// ==================== SETTINGS ACTIONS ====================

async function saveSettings(event) {
    const form = document.getElementById('settingsForm');
    const formData = new FormData(form);
    const data = {};
    
    for (const [key, value] of formData.entries()) {
        if (key.startsWith('config_')) {
            data[key] = value;
        }
    }
    
    try {
        const result = await apiCall('update_settings', data);
        
        if (result.success) {
            showNotification(result.message, 'success');
        }
    } catch (error) {}
}

// ==================== FILTER FUNCTIONS ====================

function filterUsers() {
    const search = document.getElementById('userSearch')?.value || '';
    const verified = document.getElementById('userVerifiedFilter')?.value || '';
    const banned = document.getElementById('userBannedFilter')?.value || '';
    
    let url = window.location.pathname;
    const params = new URLSearchParams();
    
    if (search) params.set('user_search', search);
    if (verified) params.set('user_verified', verified);
    if (banned) params.set('user_banned', banned);
    
    window.location.href = url + (params.toString() ? '?' + params.toString() : '');
}

function filterLogs() {
    const type = document.getElementById('logTypeFilter')?.value || '';
    const user = document.getElementById('logUserFilter')?.value || '';
    
    let url = window.location.pathname;
    const params = new URLSearchParams();
    
    if (type) params.set('log_type', type);
    if (user) params.set('log_user', user);
    
    window.location.href = url + (params.toString() ? '?' + params.toString() : '');
}

// ==================== REFRESH FUNCTIONS ====================

async function refreshPendingCounts() {
    try {
        // This would ideally call an API to get updated counts
        // For now, we'll just reload the page after a delay
        setTimeout(() => window.location.reload(), 2000);
    } catch (error) {
        console.error('Error refreshing counts:', error);
    }
}

// ==================== EXPORT FUNCTIONS ====================

// Make functions globally available
window.verifyDeposit = verifyDeposit;
window.rejectDeposit = rejectDeposit;
window.processWithdrawal = processWithdrawal;
window.completeWithdrawal = completeWithdrawal;
window.rejectWithdrawal = rejectWithdrawal;
window.showUserDetails = showUserDetails;
window.toggleUserBan = toggleUserBan;
window.adjustBalance = adjustBalance;
window.submitBalanceAdjustment = submitBalanceAdjustment;
window.createToken = createToken;
window.editToken = editToken;
window.verifyKyc = verifyKyc;
window.openKycModal = openKycModal;
window.verifyKycFromModal = verifyKycFromModal;
window.viewKycDocument = viewKycDocument;
window.filterUsers = filterUsers;
window.filterLogs = filterLogs;
window.saveSettings = saveSettings;
window.viewScreenshot = viewScreenshot;