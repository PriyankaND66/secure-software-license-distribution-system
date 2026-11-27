/**
 * API Client Utility Module
 * Handles JWT token storage, authenticated requests, error dispatching,
 * and license file download orchestration.
 */

const API_BASE = '/api/v1';

const Auth = {
    getToken: () => localStorage.getItem('cns_auth_token'),
    setToken: (token) => localStorage.setItem('cns_auth_token', token),
    getUser: () => {
        const u = localStorage.getItem('cns_user_info');
        return u ? JSON.parse(u) : null;
    },
    setUser: (user) => localStorage.setItem('cns_user_info', JSON.stringify(user)),
    clear: () => {
        localStorage.removeItem('cns_auth_token');
        localStorage.removeItem('cns_user_info');
    },
    isAuthenticated: () => !!localStorage.getItem('cns_auth_token'),
    requireAuth: (requiredRole = null) => {
        const token = Auth.getToken();
        const user = Auth.getUser();
        if (!token || !user) {
            window.location.href = '/ui/login.html';
            return false;
        }
        if (requiredRole && user.role !== requiredRole) {
            alert(`Access Denied: ${requiredRole} privileges required.`);
            window.location.href = user.role === 'ADMIN' ? '/ui/admin.html' : '/ui/dashboard.html';
            return false;
        }
        return true;
    },
    logout: () => {
        Auth.clear();
        window.location.href = '/ui/login.html';
    }
};

async function apiRequest(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = options.headers || {};

    headers['Content-Type'] = headers['Content-Type'] || 'application/json';

    const token = Auth.getToken();
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    try {
        const response = await fetch(url, { ...options, headers });
        if (response.status === 401) {
            Auth.clear();
            if (!window.location.pathname.includes('login.html')) {
                window.location.href = '/ui/login.html';
            }
            throw new Error('Session expired. Please log in again.');
        }

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || data.message || `Request failed (${response.status})`);
        }
        return data;
    } catch (err) {
        console.error(`API Error on ${endpoint}:`, err);
        throw err;
    }
}

// Direct File Download Utility for license.lic
async function downloadLicenseFile(licenseId) {
    const url = `${API_BASE}/licenses/${licenseId}/download`;
    const token = Auth.getToken();
    
    try {
        const resp = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        if (!resp.ok) {
            const err = await resp.json();
            throw new Error(err.detail || 'Download failed');
        }
        const blob = await resp.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `license_${licenseId}.lic`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(downloadUrl);
    } catch (e) {
        alert(`Failed to download license: ${e.message}`);
    }
}

// UI Alert Helper
function showAlert(elementId, message, isError = true) {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.textContent = message;
    el.className = isError ? 'alert alert-error' : 'alert alert-success';
    el.style.display = 'block';
}
