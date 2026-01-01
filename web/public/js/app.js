// --- CONFIGURATION ---
const API_BASE_URL = window.location.origin;
const DEFAULT_IMAGE = 'https://images.unsplash.com/photo-1546069901-ba9599a7e63c?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80';

// Global State
let globalProducts = [];
let globalCategories = [];
let dashboardInterval = null; // To handle polling

// --- ROUTER LOGIC ---

// Map URL paths to STATIC FILE paths
const routes = {
    '/seller/dashboard': '/static/views/dashboard.html',
    '/seller/menu':      '/static/views/menu.html',
    '/seller/orders':    '/static/views/orders.html',
    '/seller/reports':   '/static/views/reports.html',
    '/seller/store-profile':   '/static/views/profile.html',
    '/seller/store-reviews':   '/static/views/reviews.html',

    //Admin Routes
    '/admin/dashboard': '/static/views/admin_dashboard.html',
    '/admin/verifications/seller': '/static/views/admin_verification_seller.html',
    '/admin/verifications/menu':    '/static/views/admin_verification_menu.html',
    '/admin/list/users': '/static/views/admin_users.html',
    '/admin/list/sellers': '/static/views/admin_sellers.html',
    '/admin/data/foods': '/static/views/admin_foods.html',
    '/admin/data/ai-analytics': '/static/views/admin_ai.html',
    '/admin/security/logs': '/static/views/admin_auth_logs.html',
    '/admin/system/access': '/static/views/admin_access.html',
    '/admin/system/health': '/static/views/admin_health.html',
    '/admin/system/settings': '/static/views/admin_settings.html',
    
    // Fallback
    '/': '/static/views/dashboard.html'
};

const router = async () => {
    let path = window.location.pathname;
    
    // Handle root
    if (path === '/' || path === '/index.html') path = '/seller/dashboard';
    
    // Get Route
    const route = routes[path] || routes['/seller/dashboard'];

    // 2. SIDEBAR LOGIC (Simplified)
    // We removed the "hide sidebar for admin" block because:
    // - Admin Login is now a standalone file (app.js doesn't run there).
    // - Admin Dashboard (admin_index.html) HAS a sidebar, so we want it visible.
    
    // Simply handle active state for whatever sidebar is present
    document.querySelectorAll('.sidebar-item').forEach(el => {
        // Reset state (works for both Admin and Seller sidebars)
        el.classList.remove('active', 'text-brand-600', 'bg-brand-50', 'border-r-4', 'border-brand-600');
        el.classList.remove('text-gray-900', 'bg-gray-50'); // Remove Admin specific active styles if any
        
        // Default Inactive State
        el.classList.add('text-gray-500', 'hover:text-brand-600', 'hover:bg-brand-50');
        
        // Check Match
        if(el.getAttribute('href') === path) {
            el.classList.remove('text-gray-500', 'hover:text-brand-600', 'hover:bg-brand-50');
            
            if (path.startsWith('/admin')) {
                // Active State for Admin (Darker Theme)
                el.classList.add('active', 'text-gray-900', 'bg-gray-50', 'border-r-4', 'border-gray-900');
            } else {
                // Active State for Seller (Blue Theme)
                el.classList.add('active', 'text-brand-600', 'bg-brand-50', 'border-r-4', 'border-brand-600');
            }
        }
    });

    // 3. Fetch View
    try {
        const response = await fetch(route);
        if(!response.ok) throw new Error("View not found: " + route);
        const html = await response.text();
        document.getElementById('app').innerHTML = html;

        // 4. INIT PAGE LOGIC
        if (dashboardInterval) clearInterval(dashboardInterval);

        // Seller Pages
        if (path === '/seller/menu') initMenuPage();
        else if (path === '/seller/dashboard') initDashboardPage();
        else if (path === '/seller/orders') initOrdersPage();
        else if (path === '/seller/reports') initReportsPage();
        else if (path === '/seller/store-reviews') initReviewsPage();
        else if (path === '/seller/store-profile') initProfilePage();
        
        // Admin Pages
        else if (path === '/admin/dashboard') initAdminDashboard();
        else if (path === '/admin/verifications/seller') initSellerRequestsPage();
        else if (path === '/admin/verifications/menu') initMenuRequestsPage();
        else if (path === '/admin/list/users') initUserManagement();
        else if (path === '/admin/list/sellers') initSellerManagement();
        else if (path === '/admin/data/foods') initFoodDatabase();
        else if (path === '/admin/data/ai-analytics') initAIPage();
        else if (path === '/admin/security/logs') initAuthLogsPage();
        else if (path === '/admin/system/access') initAdminAccessPage();
        else if (path === '/admin/system/health') initServerHealthPage();
        else if (path === '/admin/system/settings') initSettingsPage();

    } catch (error) {
        console.error(error);
        document.getElementById('app').innerHTML = `<div class="p-10 text-center text-gray-400">Page not found or content missing.</div>`;
    }
};

// Navigate without reload
const navigateTo = url => {
    history.pushState(null, null, url);
    router();
};

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    document.body.addEventListener('click', e => {
        const link = e.target.closest('[data-link]');
        if (link) {
            e.preventDefault();
            navigateTo(link.href);
        }
    });
    router();
});

window.addEventListener('popstate', router);

// =========================================================
//  SECTION: DASHBOARD LOGIC
// =========================================================

let dashboardSocket = null;

function initDashboardPage() {
    console.log("Dashboard Initialized - Realtime Mode");

    // 1. Initial Load
    loadDashboardData();

    // 2. Connect WebSocket
    connectDashboardSocket();

    checkSellerStatus();
}

function connectDashboardSocket() {
    if (dashboardSocket) {
        dashboardSocket.close();
    }

    // Determine WS Protocol (ws:// or wss://)
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/seller/ws`;

    dashboardSocket = new WebSocket(wsUrl);

    dashboardSocket.onopen = () => {
        console.log("✅ WebSocket Connected");
    };

    dashboardSocket.onmessage = (event) => {
        const msg = event.data;
        if (msg === "REFRESH") {
            console.log("🔔 Realtime Update Received!");
            // Re-fetch data immediately
            loadDashboardData();
        }
    };

    dashboardSocket.onclose = () => {
        console.log("⚠️ WebSocket Disconnected. Reconnecting in 5s...");
        setTimeout(connectDashboardSocket, 5000); // Auto-reconnect
    };

    dashboardSocket.onerror = (err) => {
        console.error("WebSocket Error:", err);
        dashboardSocket.close();
    };
}

async function loadDashboardData() {
    await Promise.all([
        fetchIncomingOrders(),
        fetchActiveOrders(),
        fetchStatsAndProfile()
    ]);
}

async function checkSellerStatus() {
    try {
        const res = await fetch(`${API_BASE_URL}/seller/profile`);
        if(res.ok) {
            const data = await res.json();
            
            const container = document.getElementById('dashboard-alerts');
            if(!container) return;
            container.innerHTML = ''; 

            // --- ROBUST STATUS CHECK ---
            // Handle both String ("suspended") and Object ({seller_admin_status: "suspended"}) formats
            let adminStatus = 'active';
            
            if (data.admin_status) {
                if (typeof data.admin_status === 'string') {
                    adminStatus = data.admin_status; // Case: Seller API
                } else if (data.admin_status.seller_admin_status) {
                    adminStatus = data.admin_status.seller_admin_status; // Case: Admin API
                }
            }

            // 1. CHECK SUSPENDED STATUS
            if (adminStatus.toLowerCase() === 'suspended') {
                const reason = data.suspension_reason || "Pemeriksaan kepatuhan atau pelanggaran kebijakan.";
                
                container.innerHTML += `
                    <div class="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-xl shadow-sm flex items-start gap-4 mb-6">
                        <div class="p-2 bg-red-100 rounded-full text-red-600 flex-shrink-0">
                            <i class="fas fa-store-slash text-lg"></i>
                        </div>
                        <div class="flex-1">
                            <h4 class="font-bold text-red-800">Akun Toko Ditangguhkan (Suspended)</h4>
                            <p class="text-sm text-red-600 mt-1">
                                Aktivitas penjualan Anda dihentikan sementara. Anda tidak dapat menerima pesanan baru.
                            </p>
                            <div class="mt-2 bg-red-100/50 p-2 rounded border border-red-200">
                                <p class="text-xs font-bold text-red-800 uppercase">Alasan:</p>
                                <p class="text-sm text-red-700 italic">"${reason}"</p>
                            </div>
                        </div>
                    </div>
                `;
                
                // Force Shop Toggle to OFF
                const toggle = document.getElementById('isOpen');
                if(toggle) { 
                    toggle.checked = false; 
                    toggle.disabled = true;
                    // Update label text if exists
                    const label = document.getElementById('statusText'); // Assuming you have this ID for the text next to toggle
                    if(label) {
                        label.innerText = "Toko Ditangguhkan";
                        label.className = "text-xs font-bold text-red-500 mt-1";
                    }
                }
            }

            // 2. CHECK VERIFICATION STATUS (Pending)
            if (data.verification_status === 'pending') {
                container.innerHTML += `
                    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded-r-xl shadow-sm flex items-start gap-4 mb-6">
                        <div class="p-2 bg-yellow-100 rounded-full text-yellow-600 flex-shrink-0">
                            <i class="fas fa-clock text-lg"></i>
                        </div>
                        <div>
                            <h4 class="font-bold text-yellow-800">Menunggu Verifikasi</h4>
                            <p class="text-sm text-yellow-700 mt-1">
                                Dokumen toko Anda sedang ditinjau oleh tim kami. 
                            </p>
                        </div>
                    </div>
                `;
            } 
            
            // 3. CHECK VERIFICATION STATUS (Rejected)
            else if (data.verification_status === 'rejected') {
                 container.innerHTML += `
                    <div class="bg-orange-50 border-l-4 border-orange-500 p-4 rounded-r-xl shadow-sm flex items-start gap-4 mb-6">
                        <div class="p-2 bg-orange-100 rounded-full text-orange-600 flex-shrink-0">
                            <i class="fas fa-exclamation-circle text-lg"></i>
                        </div>
                        <div>
                            <h4 class="font-bold text-orange-800">Verifikasi Ditolak</h4>
                            <p class="text-sm text-orange-700 mt-1">
                                Mohon periksa kembali data dokumen Anda dan ajukan ulang.
                            </p>
                            <a href="/seller/store-profile" class="mt-2 inline-block text-xs font-bold bg-orange-600 text-white px-3 py-1.5 rounded hover:bg-orange-700 transition">Perbarui Dokumen</a>
                        </div>
                    </div>
                `;
            }
        }
    } catch(e) { console.error("Status Check Error", e); }
}

// 1. FETCH INCOMING (Status: "Waiting for Confirmation")
async function fetchIncomingOrders() {
    try {
        const res = await fetch(`${API_BASE_URL}/seller/orders/incoming`);
        if (!res.ok) throw new Error("Failed");
        
        const orders = await res.json();
        // Strict Filter just in case backend sends Pending Payment
        const incoming = (orders || []).filter(o => o.status === 'Waiting for Confirmation');
        renderIncoming(incoming);
    } catch (e) { 
        console.error("Incoming Error", e);
        const el = document.getElementById('col-incoming');
        if(el) el.innerHTML = `<div class="text-center text-red-400 text-sm py-10">Gagal memuat data.</div>`;
    }
}

// 2. FETCH ACTIVE (Status: "Preparing", "Ready to Pick Up", "On Delivery")
async function fetchActiveOrders() {
    try {
        const res = await fetch(`${API_BASE_URL}/seller/orders/active`);
        if (!res.ok) throw new Error("Failed");

        const orders = await res.json();
        
        // Filter by EXACT DB String
        const preparing = orders.filter(o => o.status === 'Preparing');
        const readyAndDelivery = orders.filter(o => 
            o.status === 'Ready to Pick Up' || o.status === 'On Delivery'
        );

        renderPreparing(preparing);
        renderReady(readyAndDelivery);
        
        // Update Stat
        const activeStat = document.getElementById('stat-active');
        if(activeStat) activeStat.innerText = preparing.length + readyAndDelivery.length;

    } catch (e) { console.error("Active Error", e); }
}

// 3. FETCH STATS
async function fetchStatsAndProfile() {
    try {
        // --- A. Income Logic (Existing) ---
        const resHist = await fetch(`${API_BASE_URL}/seller/orders/history?limit=100`);
        if(resHist.ok) {
            const history = await resHist.json();
            const today = new Date().toISOString().split('T')[0];
            let income = 0;
            
            if(Array.isArray(history)) {
                history.forEach(o => {
                    if (o.created_at && o.status === 'Completed') {
                        const orderDate = new Date(o.created_at).toISOString().split('T')[0];
                        if (orderDate === today) income += o.total_price;
                    }
                });
            }
            const statIncome = document.getElementById('stat-income');
            if(statIncome) statIncome.innerText = formatRupiah(income);
        }

        // --- B. Profile Rating Logic (FIXED) ---
        const resProf = await fetch(`${API_BASE_URL}/seller/profile`);
        if(resProf.ok) {
            const profile = await resProf.json();
            
            // KEY FIX: Use 'average_rating' instead of 'rating'
            const ratingVal = profile.average_rating || 0; 
            
            const statRating = document.getElementById('stat-rating');
            if(statRating) {
                statRating.innerText = ratingVal.toFixed(1);
            }
        }

    } catch (e) { console.error("Stats Error", e); }
}

// --- RENDERERS ---

function renderIncoming(orders) {
    const container = document.getElementById('col-incoming');
    const badge = document.getElementById('badge-incoming');
    const statNew = document.getElementById('stat-new');

    if(!container) return;
    if(badge) badge.innerText = orders.length;
    if(statNew) statNew.innerText = orders.length;
    
    if (orders.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-400 text-sm py-10">Tidak ada pesanan baru.</div>`;
        return;
    }
    container.innerHTML = orders.map(order => createOrderCard(order)).join('');
}

function renderPreparing(orders) {
    const container = document.getElementById('col-preparing');
    const badge = document.getElementById('badge-preparing');
    
    if(!container) return;
    if(badge) badge.innerText = orders.length;

    if (orders.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-400 text-sm py-10 opacity-50">Tidak ada antrian.</div>`;
        return;
    }
    container.innerHTML = orders.map(order => createOrderCard(order)).join('');
}

function renderReady(orders) {
    const container = document.getElementById('col-ready');
    const badge = document.getElementById('badge-ready');
    
    if(!container) return;
    if(badge) badge.innerText = orders.length;

    if (orders.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-400 text-sm py-10 opacity-50">Belum ada yang siap.</div>`;
        return;
    }
    container.innerHTML = orders.map(order => createOrderCard(order)).join('');
}

// --- CARD & BUTTON LOGIC ---

function createOrderCard(order) {
    let time = "N/A";
    if(order.created_at) {
        time = new Date(order.created_at).toLocaleTimeString('id-ID', {hour: '2-digit', minute:'2-digit'});
    }
    
    const price = formatRupiah(order.total_price);
    const initials = order.customer_name ? order.customer_name.substring(0,2).toUpperCase() : 'CS';
    
    const itemsHtml = (order.items || []).map(item => `
        <div class="flex justify-between text-xs text-gray-600 mb-1">
            <span>${item.quantity}x ${item.food_name}</span>
        </div>
    `).join('');

    // DYNAMIC BUTTON GENERATION
    let buttons = '';
    const status = order.status; 

    if (status === 'Waiting for Confirmation') {
        // Accept -> Preparing | Reject -> Rejected
        buttons = `
            <div class="flex gap-2 mt-3 pt-3 border-t border-dashed border-gray-100">
                <button onclick="updateOrderStatus('${order.order_id}', 'Preparing')" class="flex-1 bg-brand-600 hover:bg-brand-700 text-white text-xs font-bold py-2 rounded-lg transition shadow-sm">
                    Terima
                </button>
                <button onclick="openRejectModal('${order.order_id}')" class="bg-red-50 hover:bg-red-100 text-red-600 px-3 py-2 rounded-lg transition border border-red-100">
                    <i class="fas fa-times"></i>
                </button>
            </div>`;
    } 
    else if (status === 'Preparing') {
        // Selesai -> Ready to Pick Up
        buttons = `
            <button onclick="updateOrderStatus('${order.order_id}', 'Ready to Pick Up')" class="w-full mt-3 border border-green-500 text-green-600 hover:bg-green-50 text-xs font-bold py-2 rounded-lg transition">
                <i class="fas fa-check mr-1"></i> Selesai (Ready)
            </button>`;
    } 
    else if (status === 'Ready to Pick Up') {
        // Diambil Kurir -> On Delivery
        buttons = `
            <div class="mt-3 space-y-2">
                <div class="text-center text-xs font-bold text-green-600 bg-green-50 py-1 rounded">Siap Diambil</div>
                <button onclick="updateOrderStatus('${order.order_id}', 'On Delivery')" class="w-full bg-blue-50 text-blue-600 hover:bg-blue-100 text-xs font-bold py-2 rounded-lg transition">
                    <i class="fas fa-truck mr-1"></i> Telah diambil kurir
                </button>
            </div>`;
    }
    else if (status === 'On Delivery') {
        // Optional: Complete
        buttons = `
            <div class="mt-3 flex justify-between items-center text-xs font-bold text-orange-600 bg-orange-50 px-3 py-2 rounded-lg">
                <span><i class="fas fa-motorcycle"></i> Diantar</span>
                <button onclick="updateOrderStatus('${order.order_id}', 'Completed')" class="text-green-700 underline hover:text-green-900">Selesaikan</button>
            </div>`;
    }

    return `
        <div class="bg-white border border-gray-200 p-4 rounded-xl shadow-sm hover:shadow-md transition group animate-fade-in relative">
            ${status === 'On Delivery' ? '<div class="absolute top-0 right-0 w-2 h-2 bg-orange-500 rounded-full m-2 animate-pulse"></div>' : ''}
            
            <div class="flex justify-between mb-2">
                <span class="text-[10px] font-bold text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded">#${order.order_id.substring(0,8)}</span>
                <span class="text-xs font-bold text-gray-500">${time}</span>
            </div>
            
            <div class="flex items-center gap-3 mb-3">
                <div class="w-8 h-8 rounded-full bg-brand-50 text-brand-600 flex items-center justify-center font-bold text-xs border border-brand-100">${initials}</div>
                <div>
                    <h4 class="font-bold text-sm text-gray-800 leading-tight">${order.customer_name || 'Guest'}</h4>
                    <p class="text-[10px] text-gray-400 truncate w-32">${order.customer_username || ''}</p>
                </div>
            </div>

            <div class="space-y-1 mb-2 bg-gray-50/50 p-2 rounded-lg border border-gray-50">
                ${itemsHtml}
            </div>
            
            <div class="flex justify-between items-center text-sm font-bold text-gray-800">
                <span>Total</span>
                <span>${price}</span>
            </div>

            ${buttons}
        </div>`;
}

// --- ACTIONS ---

window.updateOrderStatus = async function(id, status, notes = "") {
    try {
        const btn = document.activeElement; 
        if(btn && btn.tagName === 'BUTTON') {
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
        }

        const res = await fetch(`${API_BASE_URL}/seller/orders/status/${id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: status, seller_notes: notes })
        });

        if (res.ok) {
            loadDashboardData();
        } else {
            const err = await res.text();
            alert("Gagal update: " + err);
            if(btn) { btn.disabled = false; btn.innerText = 'Retry'; }
        }
    } catch (e) {
        console.error("Update Error", e);
        alert("Terjadi kesalahan koneksi.");
    }
};

window.openRejectModal = function(id) {
    const modal = document.getElementById('rejectModal');
    const input = document.getElementById('rejectOrderId');
    const reason = document.getElementById('rejectReason');
    if(modal && input) {
        input.value = id;
        if(reason) reason.value = '';
        modal.classList.remove('hidden');
    }
};

window.closeRejectModal = function() {
    const modal = document.getElementById('rejectModal');
    if(modal) modal.classList.add('hidden');
};

window.confirmReject = function() {
    const id = document.getElementById('rejectOrderId').value;
    const notes = document.getElementById('rejectReason').value;
    
    if (!notes) {
        alert("Harap isi alasan penolakan.");
        return;
    }
    
    updateOrderStatus(id, 'Rejected', notes).then(() => {
        closeRejectModal();
    });
};

// =========================================================
//  SECTION: MENU PAGE LOGIC
// =========================================================

// --- CATEGORY CONFIGURATION ---
const FOOD_CATEGORIES = [
    "Non-Starchy Vegetables", "Starchy Vegetables", "Fruits", "Whole Grains", 
    "Refined Grains", "Meat & Poultry", "Seafood", "Plant-Based Protein", 
    "Dairy & Cheese", "Dairy Alternatives", "Fats & Oils", "Nuts & Seeds", 
    "Water", "Coffee & Tea", "Sugary Drinks", "Alcohol", 
    "Sweets & Desserts", "Savory Snacks", "Sauces & Condiments", "Prepared/Mixed Meals", 
    "Asian (General)", "Southeast Asian (Indonesian, Thai, Vietnamese)", 
    "East Asian (Chinese, Japanese, Korean)", "South Asian (Indian, Pakistani)", 
    "Western (General)", "American", "European", "Mediterranean", 
    "Middle Eastern", "Latin American / Mexican", "African", "Fusion / Modern"
];

// --- DROPDOWN LOGIC ---

// 1. Render the Dropdown Options
function initCategoryDropdown(selectedItems = []) {
    const container = document.getElementById('categoryDropdownList');
    if (!container) return;

    // Handle potential Postgres format "{A,B}" string
    let safeSelection = selectedItems;
    if (typeof selectedItems === 'string') {
        safeSelection = selectedItems.replace(/^\{|\}$/g, '').split(/,/).map(s => s.replace(/^"|"$/g, '').trim());
    } else if (!Array.isArray(selectedItems)) {
        safeSelection = [];
    }

    container.innerHTML = FOOD_CATEGORIES.map(cat => {
        const isChecked = safeSelection.includes(cat) ? 'checked' : '';
        return `
            <label class="flex items-center px-4 py-2 hover:bg-blue-50 cursor-pointer border-b border-gray-100 last:border-0">
                <input type="checkbox" value="${cat}" ${isChecked} 
                    onchange="updateCategoryButton()" 
                    class="form-checkbox h-4 w-4 text-blue-600 transition duration-150 ease-in-out mr-3 rounded border-gray-300">
                <span class="text-sm text-gray-700 select-none">${cat}</span>
            </label>
        `;
    }).join('');

    updateCategoryButton(); 
}

// 2. Toggle Visibility
window.toggleCategoryDropdown = function() {
    const list = document.getElementById('categoryDropdownList');
    if(list) list.classList.toggle('hidden');
};

// 3. Update Button Text
window.updateCategoryButton = function() {
    const checkboxes = document.querySelectorAll('#categoryDropdownList input[type="checkbox"]:checked');
    const checked = Array.from(checkboxes).map(cb => cb.value);
    
    const btnText = document.getElementById('categoryBtnText');
    if(!btnText) return;
    
    if (checked.length === 0) {
        btnText.innerText = "Pilih Kategori...";
        btnText.classList.add("text-gray-400");
        btnText.classList.remove("text-gray-700");
    } else if (checked.length <= 2) {
        btnText.innerText = checked.join(", ");
        btnText.classList.remove("text-gray-400");
        btnText.classList.add("text-gray-700");
    } else {
        btnText.innerText = `${checked.length} Kategori Terpilih`;
        btnText.classList.remove("text-gray-400");
        btnText.classList.add("text-gray-700");
    }
};

// 4. Close on Click Outside
document.addEventListener('click', function(e) {
    const btn = document.getElementById('categoryDropdownBtn');
    const list = document.getElementById('categoryDropdownList');
    if (btn && list && !btn.contains(e.target) && !list.contains(e.target)) {
        list.classList.add('hidden');
    }
});


// --- MAIN MENU FUNCTIONS ---

async function initMenuPage() {
    console.log("Menu Initialized");
    fetchProducts();
}

// 1. FETCH & RENDER
async function fetchProducts() {
    const grid = document.getElementById('productGrid');
    if(!grid) return;
    
    grid.innerHTML = `<div class="col-span-full text-center text-gray-400 py-10"><i class="fas fa-circle-notch fa-spin"></i> Memuat...</div>`;

    try {
        const res = await fetch(`${API_BASE_URL}/seller/menus?limit=100`);
        const data = await res.json();
        globalProducts = data || [];
        
        // --- 1. COUNT STATUS FOR BANNER ---
        const pendingCount = globalProducts.filter(p => p.is_approved === 'pending').length;
        const rejectedCount = globalProducts.filter(p => p.is_approved === 'rejected').length;
        
        renderStatusBanner(pendingCount, rejectedCount);

        // --- 2. SORTING LOGIC (NEW) ---
        // Priority: Rejected (Top) -> Pending -> Approved/Verified (Bottom)
        globalProducts.sort((a, b) => {
            const getPriority = (status) => {
                if (status === 'rejected') return 0; // Highest priority
                if (status === 'pending') return 1;  // Second priority
                return 2;                            // Normal priority
            };

            const priorityA = getPriority(a.is_approved);
            const priorityB = getPriority(b.is_approved);

            // If priorities are different, sort by priority
            if (priorityA !== priorityB) {
                return priorityA - priorityB;
            }
            
            // If priorities are same, sort by newest created_at
            return new Date(b.created_at) - new Date(a.created_at);
        });

        // --- 3. RENDER GRID ---
        renderGrid(globalProducts);
        
    } catch (error) {
        console.error(error);
        grid.innerHTML = `<div class="col-span-full text-center text-red-500 py-10">Gagal mengambil data.</div>`;
    }
}

// 2. RENDER STATUS BANNER
function renderStatusBanner(pending, rejected) {
    const container = document.getElementById('menu-status-section');
    if (!container) return;
    
    container.innerHTML = ''; // Clear previous content
    
    // Hide if no issues
    if (pending === 0 && rejected === 0) {
        container.classList.add('hidden');
        return;
    }
    
    container.classList.remove('hidden');

    if (rejected > 0) {
        container.innerHTML += `
            <div class="bg-red-50 border-l-4 border-red-500 p-4 rounded-r-xl shadow-sm flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="p-2 bg-red-100 rounded-full text-red-600"><i class="fas fa-exclamation-circle"></i></div>
                    <div>
                        <h4 class="font-bold text-red-800 text-sm">Menu Ditolak</h4>
                        <p class="text-xs text-red-600">${rejected} item ditolak oleh admin. Silakan periksa dan revisi.</p>
                    </div>
                </div>
            </div>`;
    }

    if (pending > 0) {
        container.innerHTML += `
            <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded-r-xl shadow-sm flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="p-2 bg-yellow-100 rounded-full text-yellow-600"><i class="fas fa-clock"></i></div>
                    <div>
                        <h4 class="font-bold text-yellow-800 text-sm">Menunggu Verifikasi</h4>
                        <p class="text-xs text-yellow-700">${pending} item sedang dalam peninjauan admin dan belum tampil di aplikasi.</p>
                    </div>
                </div>
            </div>`;
    }
}

function renderGrid(products) {
    const grid = document.getElementById('productGrid');
    if(!grid) return;
    grid.innerHTML = '';
    
    if (!products || products.length === 0) {
        grid.innerHTML = `<div class="col-span-full text-center text-gray-400 py-20 bg-white rounded-2xl border border-dashed">Belum ada menu.</div>`;
        return;
    }

    products.forEach(item => {
        let img = item.thumbnail_url || item.photo_url || DEFAULT_IMAGE;
        const price = formatRupiah(item.price);
        
        // --- BADGE LOGIC ---
        let badge = '';
        if (item.is_approved === 'rejected') {
            badge = `<span class="bg-red-500 text-white px-2 py-1 text-[10px] rounded font-bold uppercase shadow-sm">Ditolak</span>`;
        } else if (item.is_approved === 'pending') {
            badge = `<span class="bg-yellow-400 text-yellow-900 px-2 py-1 text-[10px] rounded font-bold uppercase shadow-sm">Pending</span>`;
        } else if (!item.is_available) {
            badge = `<span class="bg-gray-700 text-white px-2 py-1 text-[10px] rounded font-bold uppercase shadow-sm">Habis</span>`;
        } else {
            badge = `<span class="bg-green-100 text-green-700 px-2 py-1 text-[10px] rounded font-bold uppercase">Ready</span>`;
        }

        const card = document.createElement('div');
        card.className = 'bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden hover:shadow-lg transition group';
        card.innerHTML = `
            <div class="h-44 relative overflow-hidden bg-gray-100">
                <img src="${img}" class="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110">
                <div class="absolute top-3 right-3 flex flex-col gap-1 items-end">${badge}</div>
                <div class="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition flex items-center justify-center gap-3">
                    <button onclick="editProduct('${item.food_id}')" class="w-10 h-10 rounded-full bg-white text-brand-600 shadow"><i class="fas fa-pencil-alt"></i></button>
                    <button onclick="deleteProduct('${item.food_id}')" class="w-10 h-10 rounded-full bg-white text-red-500 shadow"><i class="fas fa-trash"></i></button>
                </div>
            </div>
            <div class="p-4">
                <h4 class="font-bold text-gray-800 truncate text-sm" title="${item.food_name}">${item.food_name}</h4>
                <div class="flex justify-between items-center mt-1">
                    <p class="text-brand-600 font-extrabold text-sm">${price}</p>
                    <span class="text-[10px] text-gray-400 font-mono">Stock: ${item.stock_count === -1 ? '∞' : item.stock_count}</span>
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

// 2. MODAL LOGIC (OPEN/CLOSE)
window.openProductModal = function() {
    const modal = document.getElementById('productModal');
    if(!modal) return;

    // Reset Form
    document.getElementById('productForm').reset();
    document.getElementById('foodId').value = ''; 
    document.getElementById('modalTitle').innerText = 'Tambah Menu Baru';
    
    // --- RESET STATUS ELEMENTS ---
    document.getElementById('modal-pending-alert').classList.add('hidden');
    document.getElementById('modal-rejection-alert').classList.add('hidden');

    // Reset Image Preview
    const preview = document.getElementById('previewImage');
    const placeholder = document.getElementById('uploadPlaceholder');
    preview.src = '';
    preview.classList.add('hidden');
    placeholder.classList.remove('hidden');

    // Reset Stock UI
    const stockInput = document.getElementById('stockCount');
    const unlimitedCheck = document.getElementById('unlimitedStock');
    unlimitedCheck.checked = false;
    stockInput.disabled = false;
    stockInput.classList.remove('bg-gray-100');
    stockInput.value = "";

    // Reset Dropdown (NEW)
    initCategoryDropdown([]);

    modal.classList.remove('hidden');
    
    // Animation Fix
    const panel = document.getElementById('modalPanel');
    setTimeout(() => {
        panel.classList.remove('opacity-0', 'scale-95');
        panel.classList.add('opacity-100', 'scale-100');
        document.getElementById('modalBackdrop').classList.remove('opacity-0');
    }, 10);
};

window.closeProductModal = function() {
    const modal = document.getElementById('productModal');
    const panel = document.getElementById('modalPanel');
    
    if(!modal) return;

    // Animation Out
    panel.classList.remove('opacity-100', 'scale-100');
    panel.classList.add('opacity-0', 'scale-95');
    document.getElementById('modalBackdrop').classList.add('opacity-0');

    setTimeout(() => {
        modal.classList.add('hidden');
    }, 300);
};

// 3. EDIT PRODUCT (Populate Fields)
window.editProduct = async function(id) {
    try {
        const res = await fetch(`${API_BASE_URL}/seller/menu/${id}`);
        const item = await res.json();
        
        window.openProductModal(); 

        const pendingAlert = document.getElementById('modal-pending-alert');
        const rejectAlert = document.getElementById('modal-rejection-alert');
        const rejectText = document.getElementById('rejectionReasonText');

        // Reset
        pendingAlert.classList.add('hidden');
        rejectAlert.classList.add('hidden');

        if (item.is_approved === 'pending') {
            pendingAlert.classList.remove('hidden');
        } else if (item.is_approved === 'rejected') {
            rejectAlert.classList.remove('hidden');
            rejectText.innerText = item.rejection_reason || "Tidak ada alasan spesifik. Silakan cek kepatuhan konten.";
        }
        
        document.getElementById('modalTitle').innerText = "Edit Menu";
        document.getElementById('foodId').value = item.food_id;
        
        // Populate Basic Fields
        document.getElementById('foodName').value = item.food_name;
        document.getElementById('price').value = item.price;
        document.getElementById('description').value = item.description || '';
        document.getElementById('isAvailable').checked = item.is_available !== false;
        
        // Image
        if(item.photo_url) {
            document.getElementById('previewImage').src = item.photo_url;
            document.getElementById('previewImage').classList.remove('hidden');
            document.getElementById('uploadPlaceholder').classList.add('hidden');
            document.getElementById('photoUrl').value = item.photo_url;
        }

        // Tags
        if(item.tags && Array.isArray(item.tags)) {
            document.getElementById('tags').value = item.tags.join(', ');
        }

        // NEW: Populate Dropdown Categories
        // Supports both Array ["A", "B"] and Postgres string "{A,B}"
        initCategoryDropdown(item.food_category || []);

        // Stock Logic
        if(item.stock_count === -1) {
            document.getElementById('unlimitedStock').checked = true;
            toggleStockOverride(document.getElementById('unlimitedStock'));
        } else {
            document.getElementById('stockCount').value = item.stock_count;
        }

        // Nutrition & Details Map (Complete List)
        const map = {
            'quantity': 'quantity', 
            'serving_size': 'servingSize', 
            'serving_size_grams': 'servingSizeGrams',
            'calories': 'calories', 
            'sugar_grams': 'sugar', 
            'glycemic_index': 'glycemicIndex',
            'carbs_grams': 'carbs', 
            'protein_grams': 'protein', 
            'fat_grams': 'fat', 
            'sodium_mg': 'sodium', 
            'cholesterol_mg': 'cholesterol',
            'saturated_fat_grams': 'saturatedFat', 
            'monounsaturated_fat_grams': 'monoFat', 
            'polyunsaturated_fat_grams': 'polyFat',
            'fiber_grams': 'fiber' // Added missing field
        };

        for (const [apiKey, elementId] of Object.entries(map)) {
            const el = document.getElementById(elementId);
            if(el && item[apiKey] !== undefined && item[apiKey] !== null) {
                el.value = item[apiKey];
            }
        }

    } catch(e) { console.error("Edit Error", e); }
};

// 4. SAVE PRODUCT
window.saveProduct = async function() {
    const btn = document.getElementById('saveBtn');
    const id = document.getElementById('foodId').value;
    const method = id ? 'PUT' : 'POST';
    const endpoint = id ? `${API_BASE_URL}/seller/menu/${id}` : `${API_BASE_URL}/seller/menu`;

    const name = document.getElementById('foodName').value;
    const price = parseFloat(document.getElementById('price').value);

    if(!name || isNaN(price)) { alert("Nama dan Harga wajib diisi"); return; }

    btn.disabled = true;
    btn.innerHTML = 'Menyimpan...';

    // Stock Logic
    let finalStock = parseInt(document.getElementById('stockCount').value);
    if(document.getElementById('unlimitedStock').checked) finalStock = -1;
    if(isNaN(finalStock) && !document.getElementById('unlimitedStock').checked) finalStock = 0;

    // Tags
    const tagString = document.getElementById('tags').value;
    const tagArray = tagString.split(',').map(s => s.trim()).filter(s => s !== "");

    // NEW: Get Selected Categories from Dropdown
    const selectedCategories = Array.from(document.querySelectorAll('#categoryDropdownList input[type="checkbox"]:checked'))
                                    .map(cb => cb.value);

    const payload = {
        food_name: name,
        description: document.getElementById('description').value,
        price: price,
        currency: "IDR",
        photo_url: document.getElementById('photoUrl').value, 
        thumbnail_url: document.getElementById('photoUrl').value,
        is_available: document.getElementById('isAvailable').checked,
        stock_count: finalStock,
        
        food_category: selectedCategories, // Sent as standard JSON array ["A", "B"]
        tags: tagArray,

        // Details
        quantity: parseFloat(document.getElementById('quantity').value) || 0,
        serving_size: document.getElementById('servingSize').value,
        serving_size_grams: parseFloat(document.getElementById('servingSizeGrams').value) || 0,
        calories: parseInt(document.getElementById('calories').value) || 0,
        carbs_grams: parseFloat(document.getElementById('carbs').value) || 0,
        protein_grams: parseFloat(document.getElementById('protein').value) || 0,
        fat_grams: parseFloat(document.getElementById('fat').value) || 0,
        sugar_grams: parseFloat(document.getElementById('sugar').value) || 0,
        sodium_mg: parseFloat(document.getElementById('sodium').value) || 0,
        glycemic_index: parseInt(document.getElementById('glycemicIndex').value) || 0,
        cholesterol_mg: parseFloat(document.getElementById('cholesterol').value) || 0,
        saturated_fat_grams: parseFloat(document.getElementById('saturatedFat').value) || 0,
        monounsaturated_fat_grams: parseFloat(document.getElementById('monoFat').value) || 0,
        polyunsaturated_fat_grams: parseFloat(document.getElementById('polyFat').value) || 0,
        fiber_grams: parseFloat(document.getElementById('fiber').value) || 0
    };

    try {
        const res = await fetch(endpoint, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if(res.ok) {
            closeProductModal();
            fetchProducts();
            alert("Berhasil menyimpan!");
        } else {
            const txt = await res.text();
            alert("Gagal: " + txt);
        }
    } catch(e) { 
        alert("Error koneksi"); 
    } finally { 
        btn.disabled = false; 
        btn.innerHTML = '<i class="fas fa-save"></i> <span>Simpan Menu</span>'; 
    }
};

// 5. UTILS (Stock Toggle & Image)
window.toggleStockOverride = function(checkbox) {
    const stockInput = document.getElementById('stockCount');
    if (checkbox.checked) {
        stockInput.value = '';
        stockInput.disabled = true;
        stockInput.placeholder = 'Unlimited (-1)';
        stockInput.classList.add('bg-gray-100');
    } else {
        stockInput.disabled = false;
        stockInput.placeholder = 'Jumlah';
        stockInput.classList.remove('bg-gray-100');
    }
};

window.handleMenuImageUpload = function(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('previewImage').src = e.target.result;
            document.getElementById('previewImage').classList.remove('hidden');
            document.getElementById('uploadPlaceholder').classList.add('hidden');
            
            // NOTE: In production, upload to server here and get URL
            document.getElementById('photoUrl').value = "https://source.unsplash.com/random/400x400/?food," + Math.random(); 
        }
        reader.readAsDataURL(input.files[0]);
    }
};

window.handleGlobalSearch = function(val) {
    const term = val.toLowerCase();
    const filtered = globalProducts.filter(p => p.food_name.toLowerCase().includes(term));
    renderGrid(filtered);
};

window.deleteProduct = async function(id) {
    if(confirm("Hapus menu ini?")) {
        await fetch(`${API_BASE_URL}/seller/menu/${id}`, { method: 'DELETE' });
        fetchProducts();
    }
};

// =========================================================
//  SECTION: GLOBAL UTILS
// =========================================================

window.formatRupiah = function(amount) {
    return new Intl.NumberFormat('id-ID', { style: 'currency', currency: 'IDR', minimumFractionDigits: 0 }).format(amount);
};

// =========================================================
//  SECTION: ORDER HISTORY LOGIC
// =========================================================

let globalOrders = []; // Store raw data for client-side filtering

function initOrdersPage() {
    console.log("Orders Page Initialized");
    fetchOrderHistory();
}

async function fetchOrderHistory() {
    const tbody = document.getElementById('ordersTableBody');
    if(!tbody) return;

    try {
        // Fetch 100 latest items to allow for client-side filtering
        const res = await fetch(`${API_BASE_URL}/seller/orders/history?limit=100`);
        if (!res.ok) throw new Error("Failed to load history");

        const data = await res.json();
        globalOrders = data || [];
        
        // Initial Render
        applyOrderFilters(); 

    } catch (e) {
        console.error(e);
        tbody.innerHTML = `<tr><td colspan="7" class="py-10 text-center text-red-500">Gagal memuat data histori.</td></tr>`;
    }
}

// --- FILTER & SORT LOGIC ---

window.toggleFilterPanel = function() {
    const panel = document.getElementById('filterPanel');
    if(panel) panel.classList.toggle('hidden');
};

window.resetOrderFilters = function() {
    document.getElementById('orderSearch').value = '';
    document.getElementById('filterStartDate').value = '';
    document.getElementById('filterEndDate').value = '';
    document.getElementById('filterMinPrice').value = '';
    document.getElementById('filterMaxPrice').value = '';
    document.getElementById('filterMinQty').value = '';
    document.getElementById('filterMaxQty').value = '';
    document.getElementById('sortOrder').value = 'date_desc';
    applyOrderFilters();
};

window.applyOrderFilters = function() {
    // 1. Get Values
    const search = document.getElementById('orderSearch').value.toLowerCase();
    const startDate = document.getElementById('filterStartDate').value;
    const endDate = document.getElementById('filterEndDate').value;
    const minPrice = parseFloat(document.getElementById('filterMinPrice').value) || 0;
    const maxPrice = parseFloat(document.getElementById('filterMaxPrice').value) || Infinity;
    const minQty = parseInt(document.getElementById('filterMinQty').value) || 0;
    const maxQty = parseInt(document.getElementById('filterMaxQty').value) || Infinity;
    const sortVal = document.getElementById('sortOrder').value;

    // 2. Filter Array
    let filtered = globalOrders.filter(order => {
        // Search (ID or Name)
        const idMatch = order.order_id.toLowerCase().includes(search);
        const nameMatch = (order.customer_name || '').toLowerCase().includes(search);
        if (!idMatch && !nameMatch) return false;

        // Date Range
        if (startDate || endDate) {
            const orderDate = new Date(order.created_at).toISOString().split('T')[0];
            if (startDate && orderDate < startDate) return false;
            if (endDate && orderDate > endDate) return false;
        }

        // Price Range
        if (order.total_price < minPrice || order.total_price > maxPrice) return false;

        // Quantity Range
        const totalItems = (order.items || []).reduce((sum, item) => sum + item.quantity, 0);
        if (totalItems < minQty || totalItems > maxQty) return false;

        return true;
    });

    // 3. Sort Array
    filtered.sort((a, b) => {
        const dateA = new Date(a.created_at);
        const dateB = new Date(b.created_at);
        const qtyA = (a.items || []).reduce((sum, i) => sum + i.quantity, 0);
        const qtyB = (b.items || []).reduce((sum, i) => sum + i.quantity, 0);

        switch(sortVal) {
            case 'date_asc': return dateA - dateB;
            case 'date_desc': return dateB - dateA;
            case 'price_asc': return a.total_price - b.total_price;
            case 'price_desc': return b.total_price - a.total_price;
            case 'qty_desc': return qtyB - qtyA;
            default: return dateB - dateA;
        }
    });

    // 4. Render
    renderOrderTable(filtered);
};

// --- RENDER TABLE ---

function renderOrderTable(orders) {
    const tbody = document.getElementById('ordersTableBody');
    const countLabel = document.getElementById('showingCount');
    
    if (countLabel) countLabel.innerText = `Menampilkan ${orders.length} pesanan`;
    if (!tbody) return;

    if (orders.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="py-20 text-center text-gray-400">Tidak ada pesanan yang cocok.</td></tr>`;
        return;
    }

    tbody.innerHTML = orders.map(order => {
        const date = new Date(order.created_at).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute:'2-digit' });
        const price = formatRupiah(order.total_price);
        const itemCount = (order.items || []).reduce((sum, item) => sum + item.quantity, 0);
        
        // Status Badge Styling
        let badgeClass = "bg-gray-100 text-gray-600";
        if(order.status === 'Completed') badgeClass = "bg-green-100 text-green-700";
        if(order.status === 'Cancelled' || order.status === 'Rejected') badgeClass = "bg-red-100 text-red-700";
        if(order.status === 'On Delivery') badgeClass = "bg-blue-100 text-blue-700";

        return `
            <tr class="hover:bg-gray-50 transition border-b border-gray-50 last:border-none group">
                <td class="py-4 px-6">
                    <span class="font-mono text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">#${order.order_id.substring(0,8)}</span>
                </td>
                <td class="py-4 px-6 text-gray-600">${date}</td>
                <td class="py-4 px-6">
                    <div class="font-bold text-gray-800">${order.customer_name || 'Guest'}</div>
                    <div class="text-xs text-gray-400">${order.customer_username || ''}</div>
                </td>
                <td class="py-4 px-6 text-center">
                    <span class="font-bold bg-brand-50 text-brand-600 px-2 py-1 rounded-lg text-xs">${itemCount} Item</span>
                </td>
                <td class="py-4 px-6 font-bold text-gray-800">${price}</td>
                <td class="py-4 px-6">
                    <span class="text-[10px] font-bold uppercase tracking-wide px-2 py-1 rounded-full ${badgeClass}">${order.status}</span>
                </td>
                <td class="py-4 px-6 text-center">
                    <button onclick='openOrderModal(${JSON.stringify(order).replace(/'/g, "&#39;")})' class="text-gray-400 hover:text-brand-600 transition">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

// --- MODAL LOGIC ---

window.openOrderModal = function(order) {
    const modal = document.getElementById('orderDetailModal');
    const content = document.getElementById('orderDetailContent');
    
    // Items List
    const itemsHtml = (order.items || []).map(item => `
        <div class="flex justify-between py-2 border-b border-dashed border-gray-100 last:border-0">
            <div>
                <span class="text-xs font-bold text-brand-600 mr-2">${item.quantity}x</span>
                <span class="text-sm text-gray-700">${item.food_name}</span>
            </div>
            <span class="text-sm font-bold text-gray-800">${formatRupiah(item.price)}</span>
        </div>
    `).join('');

    content.innerHTML = `
        <div class="grid grid-cols-2 gap-4 mb-4 text-sm">
            <div>
                <p class="text-xs text-gray-500 font-bold uppercase">Order ID</p>
                <p class="font-mono text-gray-800">#${order.order_id}</p>
            </div>
            <div class="text-right">
                <p class="text-xs text-gray-500 font-bold uppercase">Tanggal</p>
                <p class="font-medium text-gray-800">${new Date(order.created_at).toLocaleString('id-ID')}</p>
            </div>
        </div>

        <div class="bg-gray-50 p-4 rounded-xl">
            <p class="text-xs text-gray-500 font-bold uppercase mb-2">Item Pesanan</p>
            ${itemsHtml}
            <div class="flex justify-between items-center mt-3 pt-3 border-t border-gray-200">
                <span class="font-bold text-gray-800">Total Pembayaran</span>
                <span class="font-bold text-brand-600 text-lg">${formatRupiah(order.total_price)}</span>
            </div>
        </div>

        <div class="mt-4">
             <p class="text-xs text-gray-500 font-bold uppercase mb-1">Status</p>
             <span class="inline-block px-3 py-1 rounded bg-gray-100 font-bold text-sm border border-gray-200">${order.status}</span>
        </div>
    `;

    modal.classList.remove('hidden');
};

window.closeOrderModal = function() {
    document.getElementById('orderDetailModal').classList.add('hidden');
};

// =========================================================
//  SECTION: REPORTS PAGE LOGIC
// =========================================================

let revenueChartInstance = null;
let ordersChartInstance = null;

function initReportsPage() {
    console.log("Reports Page Initialized");
    
    // 1. Set Default Date (Last 30 Days)
    const today = new Date();
    const pastDate = new Date();
    pastDate.setDate(today.getDate() - 30); 

    const formatDateInput = (date) => date.toISOString().split('T')[0];
    
    const startInput = document.getElementById('reportStartDate');
    const endInput = document.getElementById('reportEndDate');

    if (startInput && endInput) {
        startInput.value = formatDateInput(pastDate);
        endInput.value = formatDateInput(today);
    }

    // 2. Load Data
    loadReportData();
}

async function loadReportData() {
    const startDate = document.getElementById('reportStartDate').value;
    const endDate = document.getElementById('reportEndDate').value;

    console.log(`Fetching Report Data: ${startDate} to ${endDate}`);
    const query = `?start=${startDate}&end=${endDate}`;

    try {
        // --- A. Fetch Summary & Top Items ---
        const resStats = await fetch(`${API_BASE_URL}/seller/stats${query}`);
        if(resStats.ok) {
            const stats = await resStats.json();
            renderReportSummary(stats);
            renderTopItems(stats.top_items || []);
        }

        // --- B. Fetch Chart Data ---
        const resChart = await fetch(`${API_BASE_URL}/seller/stats/chart${query}`);
        if(resChart.ok) {
            const chartData = await resChart.json();
            renderCharts(chartData || []);
        }

    } catch (e) {
        console.error("Reports Network Error", e);
    }
}

function renderReportSummary(data) {
    const revenue = data.total_revenue || 0;
    const orders = data.total_orders || 0;
    const avg = data.average_order_value || 0;

    document.getElementById('rep-revenue').innerText = formatRupiah(revenue);
    document.getElementById('rep-orders').innerText = orders;
    document.getElementById('rep-avg').innerText = formatRupiah(avg);
}

function renderTopItems(items) {
    const container = document.getElementById('topItemsList');
    if(!container) return;
    
    if(!items || items.length === 0) {
        container.innerHTML = `<tr><td colspan="3" class="text-center py-10 text-gray-400 text-xs">Belum ada data penjualan.</td></tr>`;
        return;
    }

    container.innerHTML = items.map((item, index) => `
        <tr class="hover:bg-gray-50 transition">
            <td class="px-5 py-3">
                <div class="flex items-center gap-3">
                    <span class="text-xs font-bold text-gray-400 w-4">#${index+1}</span>
                    <span class="font-bold text-gray-700 truncate max-w-[120px]" title="${item.food_name}">${item.food_name}</span>
                </div>
            </td>
            <td class="px-5 py-3 text-center font-mono text-gray-600 text-xs bg-gray-50 rounded">${item.total_sold}</td>
            <td class="px-5 py-3 text-right font-bold text-brand-600 text-xs">${formatRupiah(item.total_revenue)}</td>
        </tr>
    `).join('');
}

function renderCharts(data) {
    const revDiv = document.querySelector("#revenueChart");
    const ordDiv = document.querySelector("#ordersChart");
    
    if (!revDiv || !ordDiv) return;

    // Handle Empty Data
    if (!data || data.length === 0) {
        revDiv.innerHTML = `<div class="flex items-center justify-center h-full text-gray-400 text-sm">Tidak ada data.</div>`;
        ordDiv.innerHTML = `<div class="flex items-center justify-center h-full text-gray-400 text-sm">Tidak ada data.</div>`;
        return;
    }

    // Prepare Data
    const dates = data.map(d => {
        const dateObj = new Date(d.date);
        return isNaN(dateObj) ? d.date : dateObj.toLocaleDateString('id-ID', {day: 'numeric', month: 'short'});
    });
    const revenues = data.map(d => d.revenue || 0);
    const orders = data.map(d => d.orders || 0);

    // =============================
    // 1. REVENUE CHART (Area)
    // =============================
    const revOptions = {
        series: [{ name: 'Pendapatan', data: revenues }],
        chart: {
            type: 'area',
            height: 280,
            fontFamily: 'Plus Jakarta Sans, sans-serif',
            toolbar: { show: false },
            zoom: { enabled: false }
        },
        stroke: { curve: 'smooth', width: 2 },
        fill: {
            type: 'gradient',
            gradient: {
                shadeIntensity: 1,
                opacityFrom: 0.7,
                opacityTo: 0.3, // Fade out effect like reference
                stops: [0, 90, 100]
            }
        },
        colors: ['#0ea5e9'], // Brand Blue
        dataLabels: { enabled: false },
        labels: dates,
        xaxis: {
            type: 'category',
            tooltip: { enabled: false },
            axisBorder: { show: false },
            axisTicks: { show: false },
            labels: { style: { colors: '#94a3b8', fontSize: '11px' } }
        },
        yaxis: {
            labels: {
                formatter: (value) => {
                    if(value >= 1000000) return (value/1000000).toFixed(1) + "jt";
                    if(value >= 1000) return (value/1000).toFixed(0) + "rb";
                    return value;
                },
                style: { colors: '#94a3b8', fontSize: '11px' }
            }
        },
        grid: { borderColor: '#f1f5f9', strokeDashArray: 4 },
        tooltip: {
            y: { formatter: (val) => formatRupiah(val) }
        }
    };

    // =============================
    // 2. ORDERS CHART (Bar)
    // =============================
    const ordOptions = {
        series: [{ name: 'Orders', data: orders }],
        chart: {
            type: 'bar',
            height: 250,
            fontFamily: 'Plus Jakarta Sans, sans-serif',
            toolbar: { show: false }
        },
        plotOptions: {
            bar: {
                columnWidth: '40%', // Nice spacing
                borderRadius: 4
            }
        },
        colors: ['#fb923c'], // Orange
        dataLabels: { enabled: false },
        labels: dates,
        xaxis: {
            type: 'category',
            tooltip: { enabled: false },
            axisBorder: { show: false },
            axisTicks: { show: false },
            labels: { style: { colors: '#94a3b8', fontSize: '11px' } }
        },
        yaxis: {
            labels: {
                formatter: (val) => val.toFixed(0),
                style: { colors: '#94a3b8', fontSize: '11px' }
            }
        },
        grid: { borderColor: '#f1f5f9', strokeDashArray: 4 },
        tooltip: {
            y: { formatter: (val) => val + " Pesanan" }
        }
    };

    // Render Charts
    revDiv.innerHTML = "";
    ordDiv.innerHTML = "";

    if (revenueChartInstance) revenueChartInstance.destroy();
    if (ordersChartInstance) ordersChartInstance.destroy();

    revenueChartInstance = new ApexCharts(revDiv, revOptions);
    revenueChartInstance.render();

    ordersChartInstance = new ApexCharts(ordDiv, ordOptions);
    ordersChartInstance.render();
}

// =========================================================
//  SECTION: PROFILE PAGE LOGIC
// =========================================================

let profileMap = null;
let profileMarker = null;

const DEFAULT_BANNER = "https://images.unsplash.com/photo-1555396273-367ea4eb4db5?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80";
const DEFAULT_LOGO = "https://ui-avatars.com/api/?name=Store&background=random&size=200";

function initProfilePage() {
    console.log("Profile Page Initialized");
    
    // 1. Load Seller Data (Store Profile)
    renderBusinessHours();
    loadProfileData();

    // 2. Load User Account Data (Personal Profile)
    loadUserAccountData(); 

    // Toggle Listener for Shop Status
    document.getElementById('isOpen')?.addEventListener('change', (e) => {
        const txt = document.getElementById('statusText');
        if(e.target.checked) {
            txt.innerText = 'Toko Buka (Online)';
            txt.className = 'text-xs font-bold text-green-600 mt-1';
        } else {
            txt.innerText = 'Toko Tutup (Offline)';
            txt.className = 'text-xs font-bold text-red-500 mt-1';
        }
    });
}

// ---------------------------------------------------------
//  PART A: SELLER PROFILE (Store Info, Map, Hours)
// ---------------------------------------------------------

// --- RENDERERS ---
function renderBusinessHours() {
    const container = document.getElementById('business-hours-container');
    if(!container) return;

    const days = [
        { id: 'monday', label: 'Senin' }, { id: 'tuesday', label: 'Selasa' },
        { id: 'wednesday', label: 'Rabu' }, { id: 'thursday', label: 'Kamis' },
        { id: 'friday', label: 'Jumat' }, { id: 'saturday', label: 'Sabtu' },
        { id: 'sunday', label: 'Minggu' }
    ];

    let html = '';
    days.forEach(day => {
        html += `
            <div class="flex flex-col sm:flex-row gap-2 sm:items-center border-b border-gray-100 pb-2 last:border-0 last:pb-0">
                <div class="w-24 flex items-center gap-2">
                    <input type="checkbox" id="closed_${day.id}" onchange="toggleDay('${day.id}')" class="w-4 h-4 text-brand-600 rounded focus:ring-brand-500 border-gray-300">
                    <span class="text-sm font-medium text-gray-700">${day.label}</span>
                </div>
                <div class="flex items-center gap-2 flex-1" id="time_inputs_${day.id}">
                    <input type="time" id="open_${day.id}" value="09:00" class="flex-1 p-1.5 text-sm border rounded-lg bg-white text-center">
                    <span class="text-gray-400 text-xs">s/d</span>
                    <input type="time" id="close_${day.id}" value="21:00" class="flex-1 p-1.5 text-sm border rounded-lg bg-white text-center">
                </div>
                <div class="hidden text-xs text-red-500 font-bold flex-1" id="closed_label_${day.id}">TUTUP</div>
            </div>
        `;
    });
    container.innerHTML = html;
}

window.toggleDay = function(dayId) {
    const isClosed = document.getElementById(`closed_${dayId}`).checked;
    document.getElementById(`time_inputs_${dayId}`).classList.toggle('hidden', isClosed);
    document.getElementById(`closed_label_${dayId}`).classList.toggle('hidden', !isClosed);
};

window.toggleOtherCuisine = function() {
    const isChecked = document.getElementById('cuisine_other_check').checked;
    const container = document.getElementById('other_cuisine_container');
    if(isChecked) {
        container.classList.remove('hidden');
        document.getElementById('other_cuisine_input').focus();
    } else {
        container.classList.add('hidden');
    }
};

// --- DATA LOADING (SELLER) ---
async function loadProfileData() {
    try {
        const res = await fetch(`${API_BASE_URL}/seller/profile`);
        if(!res.ok) throw new Error("Failed");
        const data = await res.json();

        // Visuals
        const bannerUrl = data.banner_url || DEFAULT_BANNER;
        const logoUrl = data.logo_url || DEFAULT_LOGO;

        const bannerImg = document.getElementById('displayBanner');
        if(bannerImg) {
            bannerImg.src = bannerUrl;
            bannerImg.classList.remove('hidden');
        }
        document.getElementById('bannerUrl').value = bannerUrl;

        const logoImg = document.getElementById('displayLogo');
        if(logoImg) logoImg.src = logoUrl;
        document.getElementById('logoUrl').value = logoUrl;

        // Store Info
        document.getElementById('store_name').value = data.store_name || '';
        document.getElementById('store_phone_number').value = data.store_phone_number || '';
        document.getElementById('store_description').value = data.store_description || '';
        
        const openCheck = document.getElementById('isOpen');
        if(openCheck) {
            openCheck.checked = data.is_open;
            openCheck.dispatchEvent(new Event('change'));
        }

        // Price Range
        const price = data.price_range || 1;
        const priceRad = document.querySelector(`input[name="price_range"][value="${price}"]`);
        if(priceRad) priceRad.checked = true;

        // Cuisines
        const savedCuisines = data.cuisine_type || [];
        const predefined = ["Healthy", "Indonesian", "Western", "Asian", "Beverages", "Salad"];
        const others = [];

        savedCuisines.forEach(c => {
            const cb = document.querySelector(`input[name="cuisine_type"][value="${c}"]`);
            if (cb) cb.checked = true;
            else if (!predefined.includes(c)) others.push(c);
        });

        if (others.length > 0) {
            const otherCheck = document.getElementById('cuisine_other_check');
            if(otherCheck) {
                otherCheck.checked = true;
                toggleOtherCuisine();
                document.getElementById('other_cuisine_input').value = others.join(', ');
            }
        }

        // Business Hours
        try {
            if (data.business_hours) {
                let hoursData = data.business_hours;
                if (typeof hoursData === 'string') {
                    if (!hoursData.trim().startsWith('{')) {
                        try { hoursData = atob(hoursData); } catch (e) {}
                    }
                    hoursData = JSON.parse(hoursData);
                }
                const hours = hoursData;
                for (const [day, val] of Object.entries(hours)) {
                    if(document.getElementById(`closed_${day}`)) {
                        if (val.closed) {
                            document.getElementById(`closed_${day}`).checked = true;
                            toggleDay(day);
                        } else {
                            document.getElementById(`open_${day}`).value = val.open;
                            document.getElementById(`close_${day}`).value = val.close;
                        }
                    }
                }
            }
        } catch (e) { console.error("Hours Error", e); }

        // Location
        document.getElementById('address_line1').value = data.address_line1 || '';
        document.getElementById('address_line2').value = data.address_line2 || '';
        document.getElementById('district').value = data.district || '';
        document.getElementById('city').value = data.city || '';
        document.getElementById('province').value = data.province || '';
        document.getElementById('postal_code').value = data.postal_code || '';

        // Map
        const lat = data.latitude ? parseFloat(data.latitude) : -6.2088;
        const lng = data.longitude ? parseFloat(data.longitude) : 106.8456;
        
        setTimeout(() => initProfileMap(lat, lng), 300);

    } catch(e) { console.error("Profile Load Error", e); }
}

function initProfileMap(lat, lng) {
    if (typeof L === 'undefined') {
        console.error("Leaflet not loaded");
        document.getElementById('map').innerHTML = '<div class="text-red-500 text-center py-10">Map Error: Library Missing</div>';
        return;
    }

    document.getElementById('latitude').value = lat;
    document.getElementById('longitude').value = lng;

    if (profileMap) {
        profileMap.remove();
        profileMap = null;
    }

    const mapEl = document.getElementById('map');
    if(!mapEl) return;

    profileMap = L.map('map').setView([lat, lng], 15);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '© OpenStreetMap'
    }).addTo(profileMap);

    profileMarker = L.marker([lat, lng], {draggable: true}).addTo(profileMap);

    profileMarker.on('dragend', function (e) {
        const pos = profileMarker.getLatLng();
        document.getElementById('latitude').value = pos.lat.toFixed(7);
        document.getElementById('longitude').value = pos.lng.toFixed(7);
        updateAddressFromCoordinates(pos.lat, pos.lng);
    });

    setTimeout(() => { profileMap.invalidateSize(); }, 500);
}

// --- SAVE SELLER DATA (Matched to Go Struct) ---
async function saveProfileData() {
    const btn = document.getElementById('saveBtn');
    if(btn) { btn.disabled = true; btn.innerHTML = '<i class="fas fa-spin fa-circle-notch"></i> Menyimpan...'; }

    try {
        // 1. Gather Cuisine Types
        let cuisineTypes = Array.from(document.querySelectorAll('input[name="cuisine_type"]:checked')).map(cb => cb.value);
        if (document.getElementById('cuisine_other_check').checked) {
            const otherVal = document.getElementById('other_cuisine_input').value;
            const others = otherVal.split(',').map(s => s.trim()).filter(s => s);
            cuisineTypes = [...cuisineTypes, ...others];
        }

        // 2. Gather Business Hours
        const days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
        const businessHours = {};
        days.forEach(day => {
            businessHours[day] = {
                open: document.getElementById(`open_${day}`).value,
                close: document.getElementById(`close_${day}`).value,
                closed: document.getElementById(`closed_${day}`).checked
            };
        });

        // 3. Handle Numerics (Lat/Lng) safely to send null if empty
        const latVal = document.getElementById('latitude').value;
        const lngVal = document.getElementById('longitude').value;
        const lat = (latVal && latVal !== "") ? parseFloat(latVal) : null;
        const lng = (lngVal && lngVal !== "") ? parseFloat(lngVal) : null;

        // 4. Construct Payload matching `UpdateSellerProfileRequest`
        const payload = {
            store_name: document.getElementById('store_name').value,
            store_phone_number: document.getElementById('store_phone_number').value,
            store_description: document.getElementById('store_description').value,
            is_open: document.getElementById('isOpen').checked,
            
            price_range: parseInt(document.querySelector('input[name="price_range"]:checked')?.value || 1),
            cuisine_type: cuisineTypes,
            business_hours: businessHours,
            
            banner_url: document.getElementById('bannerUrl').value || null,
            logo_url: document.getElementById('logoUrl').value || null,

            address_line1: document.getElementById('address_line1').value,
            address_line2: document.getElementById('address_line2').value,
            district: document.getElementById('district').value,
            city: document.getElementById('city').value,
            province: document.getElementById('province').value,
            postal_code: document.getElementById('postal_code').value,
            
            latitude: lat,
            longitude: lng
        };

        const res = await fetch(`${API_BASE_URL}/seller/profile`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if(res.ok) {
            alert("Profil toko berhasil disimpan!");
            loadProfileData(); 
        } else {
            const data = await res.json();
            alert("Gagal menyimpan: " + (data.error || "Unknown error"));
        }
    } catch(e) {
        console.error(e);
        alert("Terjadi kesalahan koneksi.");
    } finally {
        if(btn) { btn.disabled = false; btn.innerHTML = '<i class="fas fa-save"></i> <span>Simpan Perubahan</span>'; }
    }
}

// ---------------------------------------------------------
//  PART B: USER ACCOUNT (Personal Info, Security & Google)
// ---------------------------------------------------------

// 1. Fetch User Data
async function loadUserAccountData() {
    try {
        const res = await fetch(`${API_BASE_URL}/profile`); 
        if(!res.ok) throw new Error("Failed to load user profile");
        
        const data = await res.json();
        const profile = data.profile; 

        // Populate Fields
        if(document.getElementById('display_user_id')) {
            document.getElementById('display_user_id').innerText = profile.user_id.substring(0, 8);
        }
        document.getElementById('account_username').value = profile.username || '';
        document.getElementById('account_email').value = profile.email || '';
        document.getElementById('account_first_name').value = profile.first_name || '';
        document.getElementById('account_last_name').value = profile.last_name || '';

        const badge = document.getElementById('email_verified_badge');
        if(badge) {
            if(profile.is_email_verified) badge.classList.remove('hidden');
            else badge.classList.add('hidden');
        }

        // Render Google Button (Logic Updated)
        renderGoogleConnectSection(profile.is_google_linked);

    } catch (e) {
        console.error("User Profile Error:", e);
    }
}

// 2. Render Google Section
function renderGoogleConnectSection(isLinked) {
    const container = document.getElementById('google-connect-container');
    if(!container) return;

    if (isLinked) {
        // State: LINKED -> Show Custom Disconnect UI
        container.innerHTML = `
            <div class="flex items-center justify-between px-4 py-3 bg-white border border-green-200 rounded-xl">
                <div class="flex items-center gap-3">
                    <img src="https://www.svgrepo.com/show/475656/google-color.svg" class="w-5 h-5">
                    <div>
                        <p class="text-sm font-bold text-gray-800">Google</p>
                        <p class="text-[10px] text-green-600 font-bold">Terhubung</p>
                    </div>
                </div>
                <button onclick="unlinkGoogleAccount()" class="text-xs font-bold text-red-500 hover:text-red-700 bg-red-50 hover:bg-red-100 px-3 py-1.5 rounded-lg transition border border-red-100">
                    Putuskan
                </button>
            </div>
        `;
    } else {
        // State: NOT LINKED -> Render Container for Google Button
        container.innerHTML = `<div id="googleBtnWrapper" class="w-full flex justify-center"></div>`;
        
        // Initialize Google Button
        setTimeout(() => {
            initGoogleLinkButton();
        }, 100);
    }
}

// 3. Initialize Google Library & Render Button
function initGoogleLinkButton() {
    if (typeof google === 'undefined') {
        console.warn("Google library not loaded yet. Waiting...");
        setTimeout(initGoogleLinkButton, 500); // Retry if script is loading
        return;
    }

    const CLIENT_ID = "269881508037-qt0cqfbeemtdj5ar4nuh0i2p4lonr5sf.apps.googleusercontent.com";

    try {
        google.accounts.id.initialize({
            client_id: CLIENT_ID,
            callback: handleGoogleLinkCallback,
            context: 'use' // Hints that this is for an existing user
        });

        // Render the Official Google Button
        // We customize it to fit the UI width
        google.accounts.id.renderButton(
            document.getElementById("googleBtnWrapper"),
            { 
                theme: "outline", 
                size: "large", 
                width: "400", // Will try to fill width
                text: "continue_with",
                shape: "rectangular",
                logo_alignment: "left"
            }
        );
    } catch (e) {
        console.error("Google Button Render Error:", e);
    }
}

// 4. Callback: Handle the ID Token returned by Google
async function handleGoogleLinkCallback(response) {
    // Show global loading if possible, or just alert
    // Since the button is controlled by Google, we can't easily add a spinner inside it.
    
    const idToken = response.credential;
    
    try {
        const res = await fetch(`${API_BASE_URL}/auth/mobile/google/link`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id_token: idToken })
        });

        const data = await res.json();

        if (res.ok) {
            alert("Berhasil menghubungkan akun Google!");
            loadUserAccountData(); // Refresh UI
        } else {
            alert("Gagal menghubungkan: " + (data.error || "Unknown error"));
        }
    } catch (e) {
        console.error(e);
        alert("Terjadi kesalahan koneksi.");
    }
}

// 5. Unlink Google Account
window.unlinkGoogleAccount = async function() {
    const password = prompt("Masukkan password anda untuk konfirmasi pemutusan akun Google:");
    if (password === null) return;
    if (!password) {
        alert("Password dibutuhkan untuk keamanan.");
        return;
    }

    try {
        const res = await fetch(`${API_BASE_URL}/auth/mobile/google/unlink`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: password })
        });

        const data = await res.json();

        if (res.ok) {
            alert("Akun Google berhasil diputus.");
            loadUserAccountData();
        } else {
            if (data.error_code === "PASSWORD_NOT_SET") {
                alert("Gagal: Password belum diatur pada akun ini.");
            } else {
                alert("Gagal: " + (data.error || "Password salah."));
            }
        }
    } catch(e) {
        alert("Terjadi kesalahan koneksi.");
    }
};

// 6. Update Personal Profile
async function updatePersonalProfile() {
    const payload = {
        first_name: document.getElementById('account_first_name').value,
        last_name: document.getElementById('account_last_name').value
    };

    try {
        const res = await fetch(`${API_BASE_URL}/profile`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if(res.ok) {
            alert("Informasi pribadi berhasil diupdate.");
            loadUserAccountData();
        } else {
            const data = await res.json();
            alert(data.error || "Gagal update profil.");
        }
    } catch(e) {
        alert("Error koneksi.");
    }
}

// 7. Update Username
async function submitUsernameChange() {
    const newUsername = document.getElementById('new_username_input').value;
    const btn = document.getElementById('btnSaveUsername');
    
    if(!newUsername) return alert("Username tidak boleh kosong");
    setLoading(btn, true);

    try {
        const res = await fetch(`${API_BASE_URL}/profile/username`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_username: newUsername })
        });
        const data = await res.json();

        if(res.ok) {
            alert("Username berhasil diganti!");
            closeModal('usernameModal');
            loadUserAccountData();
        } else {
            alert(data.error || "Gagal mengganti username");
        }
    } catch(e) {
        alert("Terjadi kesalahan sistem.");
    } finally {
        setLoading(btn, false, "Simpan");
    }
}

// 8. Request Email Change
async function submitEmailChange() {
    const newEmail = document.getElementById('new_email_input').value;
    const password = document.getElementById('email_confirm_password').value;
    const btn = document.getElementById('btnSaveEmail');

    if(!newEmail || !password) return alert("Mohon lengkapi data");
    setLoading(btn, true);

    try {
        const res = await fetch(`${API_BASE_URL}/profile/update-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ new_email: newEmail, password: password })
        });
        const data = await res.json();

        if(res.ok) {
            alert("Link verifikasi telah dikirim ke email baru Anda (" + newEmail + "). Silakan cek inbox.");
            closeModal('emailModal');
        } else {
            alert(data.error || "Gagal memproses permintaan");
        }
    } catch(e) {
        alert("Terjadi kesalahan sistem.");
    } finally {
        setLoading(btn, false, "Kirim Link");
    }
}

// 9. Change Password
async function submitPasswordChange() {
    const currentPass = document.getElementById('current_password').value;
    const newPass = document.getElementById('new_password').value;
    const confirmPass = document.getElementById('confirm_password').value;
    const btn = document.getElementById('btnSavePassword');

    if(!currentPass || !newPass || !confirmPass) return alert("Semua kolom wajib diisi");
    if(newPass !== confirmPass) return alert("Password baru tidak cocok");
    setLoading(btn, true);

    try {
        const res = await fetch(`${API_BASE_URL}/profile/password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                current_password: currentPass,
                new_password: newPass,
                confirm_password: confirmPass
            })
        });
        const data = await res.json();

        if(res.ok) {
            alert("Password berhasil diubah! Silakan login kembali.");
            closeModal('passwordModal');
            window.location.href = '/logout';
        } else {
            alert(data.error || "Gagal mengubah password");
        }
    } catch(e) {
        alert("Terjadi kesalahan sistem.");
    } finally {
        setLoading(btn, false, "Ganti Password");
    }
}

// ---------------------------------------------------------
//  PART C: SHARED UTILITIES
// ---------------------------------------------------------

window.handleImageUpload = function(input, displayId, valueId) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const display = document.getElementById(displayId);
            display.src = e.target.result;
            display.classList.remove('hidden');
            // Mock upload
            document.getElementById(valueId).value = "https://source.unsplash.com/random/800x400/?" + Math.random(); 
        }
        reader.readAsDataURL(input.files[0]);
    }
};

async function updateAddressFromCoordinates(lat, lng) {
    try {
        const inputs = ['address_line1', 'district', 'city', 'province', 'postal_code'];
        inputs.forEach(id => {
            const el = document.getElementById(id);
            if(el) el.style.opacity = '0.5';
        });

        const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}&accept-language=id`;
        const response = await fetch(url);
        if (!response.ok) throw new Error("Nominatim API Error");
        
        const data = await response.json();
        if (data && data.address) {
            const addr = data.address;
            const road = addr.road || '';
            const houseNumber = addr.house_number ? `No. ${addr.house_number}` : '';
            document.getElementById('address_line1').value = `${road} ${houseNumber}`.trim();
            document.getElementById('district').value = addr.suburb || addr.village || addr.quarter || '';
            document.getElementById('city').value = addr.city || addr.town || addr.municipality || addr.county || '';
            document.getElementById('province').value = addr.state || '';
            document.getElementById('postal_code').value = addr.postcode || '';
            
            const building = addr.building || addr.amenity || addr.shop || '';
            if(building) document.getElementById('address_line2').value = building;
        }
    } catch (error) {
        console.error("Auto-fill address failed:", error);
    } finally {
        inputs.forEach(id => {
            const el = document.getElementById(id);
            if(el) el.style.opacity = '1';
        });
    }
}

window.openModal = function(id) {
    document.getElementById(id).classList.remove('hidden');
};

window.closeModal = function(id) {
    document.getElementById(id).classList.add('hidden');
};

window.setLoading = function(btn, isLoading, originalText = "") {
    if(isLoading) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Loading...';
    } else {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
};

// =========================================================
//  SECTION: REVIEWS PAGE LOGIC (FIXED)
// =========================================================

let globalReviews = [];

function initReviewsPage() {
    console.log("Reviews Page Initialized");
    loadReviews();
}

// Attach to window to ensure global access
window.loadReviews = async function() {
    const container = document.getElementById('reviewsList');
    if (!container) return;

    try {
        const res = await fetch(`${API_BASE_URL}/seller/reviews`); 
        
        if (!res.ok) throw new Error("Failed to fetch reviews");
        
        const data = await res.json();
        globalReviews = data || []; 
        
        // 1. Calculate Stats & Render Bars
        renderReviewStats(globalReviews);
        
        // 2. Render List (Apply default filters)
        applyReviewFilters();

    } catch (e) {
        console.error(e);
        container.innerHTML = `
            <div class="bg-white rounded-2xl p-10 text-center border border-gray-200">
                <div class="text-red-100 text-5xl mb-4"><i class="fas fa-exclamation-circle"></i></div>
                <h3 class="text-lg font-bold text-gray-800">Gagal memuat ulasan</h3>
                <p class="text-gray-500 mb-6">Terjadi kesalahan saat mengambil data.</p>
                <button onclick="loadReviews()" class="bg-white border border-gray-300 text-gray-600 px-4 py-2 rounded-lg font-bold text-sm hover:bg-gray-50">Coba Lagi</button>
            </div>`;
    }
};

function renderReviewStats(reviews) {
    const total = reviews.length;
    
    // Calculate Average
    const sum = reviews.reduce((acc, r) => acc + (r.rating || 0), 0);
    const avg = total > 0 ? (sum / total).toFixed(1) : "0.0";
    
    // Update Stats Display
    const elAvg = document.getElementById('stat-avg-rating');
    const elTotal = document.getElementById('stat-total-reviews');
    
    if (elAvg) elAvg.innerText = avg;
    if (elTotal) elTotal.innerText = total;

    // Render Big Stars
    let starsHtml = '';
    const avgInt = Math.round(avg);
    const starContainer = document.getElementById('stat-stars-display');
    
    if (starContainer) {
        for(let i=1; i<=5; i++) {
            starsHtml += `<i class="fas fa-star ${i <= avgInt ? 'text-yellow-400' : 'text-gray-200'}"></i>`;
        }
        starContainer.innerHTML = starsHtml;
    }

    // Calculate Breakdown (5 stars down to 1 star)
    const counts = {5:0, 4:0, 3:0, 2:0, 1:0};
    reviews.forEach(r => {
        const rating = Math.round(r.rating);
        if(counts[rating] !== undefined) counts[rating]++;
    });

    // Render Bars
    const barsContainer = document.getElementById('star-breakdown-container');
    if (barsContainer) {
        let barsHtml = '';
        for(let i=5; i>=1; i--) {
            const count = counts[i];
            const percentage = total > 0 ? (count / total) * 100 : 0;
            
            barsHtml += `
                <div class="flex items-center gap-3 text-sm">
                    <div class="flex items-center gap-1 w-12 flex-shrink-0 font-bold text-gray-600">
                        <span>${i}</span> <i class="fas fa-star text-yellow-400 text-xs"></i>
                    </div>
                    <div class="flex-1 h-2.5 bg-gray-100 rounded-full overflow-hidden">
                        <div class="h-full bg-yellow-400 rounded-full" style="width: ${percentage}%"></div>
                    </div>
                    <div class="w-10 text-right text-gray-400 text-xs font-medium">${count}</div>
                </div>
            `;
        }
        barsContainer.innerHTML = barsHtml;
    }
}

window.applyReviewFilters = function() {
    const starFilter = document.getElementById('reviewFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const sortOrder = document.getElementById('sortOrder').value;

    // 1. Filter
    let filtered = globalReviews.filter(r => {
        // Star Filter
        if (starFilter !== 'all' && Math.round(r.rating) != starFilter) return false;
        
        // Status Filter
        if (statusFilter === 'unreplied' && r.seller_reply) return false;
        if (statusFilter === 'replied' && !r.seller_reply) return false;

        return true;
    });

    // 2. Sort
    filtered.sort((a, b) => {
        const dateA = new Date(a.created_at);
        const dateB = new Date(b.created_at);

        switch (sortOrder) {
            case 'newest': return dateB - dateA;
            case 'oldest': return dateA - dateB;
            case 'highest': return b.rating - a.rating;
            case 'lowest': return a.rating - b.rating;
            default: return dateB - dateA;
        }
    });

    renderReviews(filtered);
};

function renderReviews(reviews) {
    const container = document.getElementById('reviewsList');
    if (!container) return;

    if (reviews.length === 0) {
        container.innerHTML = `
            <div class="bg-white rounded-2xl p-16 text-center border border-dashed border-gray-300">
                <div class="text-gray-200 text-6xl mb-4"><i class="fas fa-star"></i></div>
                <h3 class="text-lg font-bold text-gray-400">Tidak ada ulasan ditemukan</h3>
                <p class="text-sm text-gray-400">Coba ubah filter pencarian anda.</p>
            </div>`;
        return;
    }

    container.innerHTML = reviews.map(r => createReviewCard(r)).join('');
}

function createReviewCard(review) {
    // Generate Stars
    let starsHtml = '';
    for (let i = 1; i <= 5; i++) {
        starsHtml += `<i class="fas fa-star ${i <= review.rating ? 'text-yellow-400' : 'text-gray-200'} text-sm"></i>`;
    }

    // Format Date
    let dateStr = "Baru saja";
    if(review.created_at) {
        try {
            dateStr = new Date(review.created_at).toLocaleDateString('id-ID', {
                day: 'numeric', month: 'long', year: 'numeric'
            });
        } catch(e) {}
    }

    // Avatar Logic
    const avatarUrl = review.customer_avatar || `https://ui-avatars.com/api/?name=${review.customer_name}&background=random`;

    // Reply Logic
    let replySection = '';
    if (review.seller_reply) {
        // ALREADY REPLIED
        replySection = `
            <div class="mt-4 bg-gray-50 rounded-xl p-4 border border-gray-100 relative">
                <div class="absolute -top-2 left-6 w-4 h-4 bg-gray-50 border-t border-l border-gray-100 transform rotate-45"></div>
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-xs font-bold text-brand-600 bg-brand-50 px-2 py-0.5 rounded">Respon Toko</span>
                </div>
                <p class="text-sm text-gray-700 leading-relaxed">${review.seller_reply}</p>
            </div>
        `;
    } else {
        // NOT REPLIED YET (Input Form)
        // Notice 'this' passed to submitReply
        replySection = `
            <div class="mt-4 pt-4 border-t border-gray-100" id="reply-box-${review.review_id}">
                <button onclick="toggleReplyForm('${review.review_id}')" class="text-xs font-bold text-brand-600 hover:text-brand-700 flex items-center gap-2 bg-brand-50 px-3 py-1.5 rounded-lg transition">
                    <i class="fas fa-reply"></i> Balas
                </button>
                
                <div id="form-${review.review_id}" class="hidden mt-3 animate-fade-in">
                    <textarea id="input-${review.review_id}" rows="3" class="w-full p-3 text-sm border border-gray-300 rounded-xl focus:ring-2 focus:ring-brand-100 focus:border-brand-500 outline-none resize-none" placeholder="Tulis balasan anda..."></textarea>
                    <div class="flex justify-end gap-2 mt-2">
                        <button onclick="toggleReplyForm('${review.review_id}')" class="text-gray-500 text-xs font-bold px-3 py-2 hover:bg-gray-100 rounded-lg">Batal</button>
                        <button onclick="submitReply('${review.review_id}', this)" class="bg-brand-600 hover:bg-brand-700 text-white text-xs font-bold px-4 py-2 rounded-lg transition shadow-sm flex items-center gap-2">
                            <span>Kirim</span> <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    return `
        <div class="bg-white rounded-2xl p-6 border border-gray-200 shadow-sm hover:shadow-md transition">
            <div class="flex justify-between items-start">
                <div class="flex gap-4">
                    <img src="${avatarUrl}" class="w-10 h-10 rounded-full object-cover border border-gray-100 bg-gray-50">
                    <div>
                        <h4 class="font-bold text-gray-800 text-sm">${review.customer_name || 'Pelanggan'}</h4>
                        <div class="flex items-center gap-2 mt-0.5">
                            <div class="flex gap-0.5">${starsHtml}</div>
                            <span class="text-[10px] text-gray-400">• ${dateStr}</span>
                        </div>
                    </div>
                </div>
            </div>

            <p class="text-gray-600 text-sm mt-4 leading-relaxed">${review.review_text || '<span class="italic text-gray-400">Tidak ada komentar tertulis.</span>'}</p>

            ${replySection}
        </div>
    `;
}

// --- UTILS FOR REVIEWS ---

window.toggleReplyForm = function(id) {
    const form = document.getElementById(`form-${id}`);
    const btn = document.querySelector(`#reply-box-${id} > button`);
    
    if (form.classList.contains('hidden')) {
        form.classList.remove('hidden');
        btn.classList.add('hidden');
    } else {
        form.classList.add('hidden');
        btn.classList.remove('hidden');
    }
};

// FIX: Accepts 'btnRef' to safely control the button without wiping document.body
window.submitReply = async function(reviewId, btnRef) {
    const input = document.getElementById(`input-${reviewId}`);
    const text = input.value.trim();

    if (!text) {
        alert("Balasan tidak boleh kosong.");
        return;
    }

    // Safe UI Loading State
    let originalContent = "Kirim";
    if(btnRef) {
        originalContent = btnRef.innerHTML;
        btnRef.disabled = true;
        btnRef.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i>';
    }

    try {
        const res = await fetch(`${API_BASE_URL}/seller/reviews/reply/${reviewId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reply_text: text })
        });

        if (res.ok) {
            alert("Balasan berhasil dikirim!");
            loadReviews(); // Reload list to show the new reply
        } else {
            const err = await res.json();
            alert("Gagal: " + (err.error || "Unknown Error"));
            if(btnRef) {
                btnRef.disabled = false;
                btnRef.innerHTML = originalContent;
            }
        }
    } catch (e) {
        console.error(e);
        alert("Terjadi kesalahan koneksi.");
        if(btnRef) {
            btnRef.disabled = false;
            btnRef.innerHTML = originalContent;
        }
    }
};

// =========================================================
//  SECTION: ADMIN SECURE API & AUTH UTILS
// =========================================================

/**
 * Wrapper for fetching Admin APIs.
 * Automatically attaches the Access Token.
 * If 401 (Unauthorized), it tries to Refresh the token and retry.
 */
window.adminFetch = async function(endpoint, options = {}) {
    let accessToken = localStorage.getItem('admin_access_token');

    // 1. Prepare Headers
    const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`,
        ...(options.headers || {})
    };

    // 2. First Attempt
    let response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers: headers
    });

    // 3. Handle 401 (Token Expired?)
    if (response.status === 401) {
        console.warn("Admin Token Expired. Attempting Refresh...");
        
        const refreshSuccess = await refreshAdminSession();
        
        if (refreshSuccess) {
            // Retry with NEW token
            const newAccessToken = localStorage.getItem('admin_access_token');
            headers['Authorization'] = `Bearer ${newAccessToken}`;
            
            response = await fetch(`${API_BASE_URL}${endpoint}`, {
                ...options,
                headers: headers
            });
        } else {
            // Refresh failed (Session dead) -> Logout
            adminLogout(false); // false = don't call API, just clear local
            throw new Error("Session Expired");
        }
    }

    return response;
};

/**
 * Calls the /auth/admin/refresh endpoint using the Refresh Token.
 * Returns true if successful, false otherwise.
 */
async function refreshAdminSession() {
    const refreshToken = localStorage.getItem('admin_refresh_token');
    if (!refreshToken) return false;

    try {
        const res = await fetch(`${API_BASE_URL}/auth/admin/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (res.ok) {
            const data = await res.json();
            localStorage.setItem('admin_access_token', data.access_token);
            console.log("Admin Session Refreshed Successfully");
            return true;
        }
    } catch (e) {
        console.error("Refresh Error:", e);
    }
    return false;
}

/**
 * Logs out the admin.
 * 1. Calls API to invalidate Refresh Token (if online).
 * 2. Clears LocalStorage.
 * 3. Redirects to Login.
 */
window.adminLogout = async function(callApi = true) {
    if (callApi) {
        const refreshToken = localStorage.getItem('admin_refresh_token');
        if (refreshToken) {
            try {
                await fetch(`${API_BASE_URL}/auth/admin/logout`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refresh_token: refreshToken })
                });
            } catch (e) {
                console.error("Logout API failed (ignoring):", e);
            }
        }
    }

    // Clear Storage
    localStorage.removeItem('admin_access_token');
    localStorage.removeItem('admin_refresh_token');
    localStorage.removeItem('admin_username');
    localStorage.removeItem('admin_role');

    // Redirect
    window.location.href = '/admin/login';
};

// =========================================================
//  SECTION: ADMIN WEBSOCKET (REAL-TIME UPDATES)
// =========================================================

let adminSocket = null;

function connectAdminWebSocket() {
    const token = localStorage.getItem('admin_access_token');
    if (!token) return; // Don't connect if not logged in

    // 1. Determine Protocol (ws:// or wss://) & Host automatically
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host; // e.g., localhost:8080 or your-ngrok-url
    const wsUrl = `${protocol}//${host}/admin/ws?token=${token}`;

    // 2. Close existing connection if any (prevents duplicates)
    if (adminSocket) {
        adminSocket.close();
    }

    // 3. Connect
    adminSocket = new WebSocket(wsUrl);

    adminSocket.onopen = function() {
        console.log("✅ Admin Live Feed Connected");
    };

    adminSocket.onmessage = function(event) {
        console.log("🔔 Admin Update:", event.data);
        try {
                const msg = JSON.parse(event.data);
               
            if (msg.type === "DASHBOARD_STATS_UPDATE" && window.location.pathname === '/admin/dashboard') {
                updateDashboardUI(msg.data);
            }
            // 2. Server Health Update (Existing)
            else if (msg.type === "SYSTEM_HEALTH_UPDATE" && window.location.pathname === '/admin/system/health') {
                updateHealthUI(msg.data);
            }
            
            } catch (e) {
                // It's a plain text string (Notification)
                console.log("🔔 Admin Notification:", event.data);

                if (event.data === "NEW_SELLER_PENDING") {
                    if (window.location.pathname === '/admin/dashboard') fetchAdminStats();
                } 
                else if (event.data === "SECURITY_ALERT") {
                    if (window.location.pathname === '/admin/dashboard') fetchAdminStats();
                }
            }
    };

    adminSocket.onclose = function() {
        console.log("⚠️ Admin Feed Disconnected. Reconnecting in 5s...");
        setTimeout(connectAdminWebSocket, 5000); // Auto-reconnect
    };

    adminSocket.onerror = function(err) {
        console.error("WebSocket Error:", err);
        adminSocket.close();
    };
}

// 4. Auto-Connect when App Loads
document.addEventListener('DOMContentLoaded', () => {
    // Only connect if we are in the admin panel and have a token
    if (window.location.pathname.startsWith('/admin') && localStorage.getItem('admin_access_token')) {
        connectAdminWebSocket();
    }
});

// =========================================================
//  SECTION: ADMIN DASHBOARD LOGIC
// =========================================================

async function initAdminDashboard() {
    console.log("Admin Dashboard Initialized");
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'Overview';

    // 1. Initial Data Fetch (HTTP) - "First Paint"
    await fetchAdminStats(); 
    
    // 2. WebSocket is handled globally by connectAdminWebSocket()
    // It will call updateDashboardUI() when messages arrive.
}

// Fetches initial full state (Stats + Lists + Logs)
async function fetchAdminStats() {
    try {
        const res = await adminFetch('/admin/dashboard/stats');
        if (!res.ok) throw new Error(`Stats Failed: ${res.status}`);
        
        const data = await res.json();
        console.log("Initial Dashboard Data:", data); // Debugging

        // 1. Update UI Elements using unified helper
        updateDashboardUI(data);

        // 2. Render Task Lists (Only available in HTTP response, not WS usually)
        if (data.tasks) {
            renderPendingSellersList(data.tasks.new_sellers || []);
            renderPendingMenusList(data.tasks.new_menus || []);
        } else {
            // Fallback if empty
            renderPendingSellersList([]);
            renderPendingMenusList([]);
        }

    } catch (e) {
        console.error("Dashboard Load Error:", e);
        // Optional: Show error state on UI
        setText('dash_total_users', '-');
        setText('dash_revenue', '-');
    }
}

// Unified UI Updater (Handles both HTTP and WebSocket Data)
function updateDashboardUI(data) {
    if (!data) return;

    // A. Stats Cards
    if (data.stats) {
        setText('dash_total_users', data.stats.total_users || 0);
        setText('dash_revenue', formatRupiah(data.stats.revenue_today || 0));
        setText('dash_pending_sellers', data.stats.pending_sellers || 0);
        setText('dash_pending_foods', data.stats.pending_foods || 0);
    }

    // B. Server Health & Latency
    if (data.server_health) {
        // CPU Load
        const loadEl = document.getElementById('dash_server_load');
        if (loadEl) {
            const cpuVal = data.server_health.cpu_load || "0%";
            loadEl.innerText = cpuVal;
            const val = parseFloat(cpuVal);
            loadEl.className = val > 80 ? "text-lg font-bold text-red-500" : 
                               val > 50 ? "text-lg font-bold text-yellow-400" : 
                               "text-lg font-bold text-green-400";
        }

        // Database Status
        const dbEl = document.getElementById('dash_db_status');
        if (dbEl) {
            // Handle HTTP (bool) vs WS (string) mismatch
            let statusText = "Healthy";
            let statusClass = "text-green-400";

            if (data.server_health.db_status) {
                // WS Format: "Healthy" or "Disconnected"
                statusText = data.server_health.db_status;
                if (statusText !== "Healthy") statusClass = "text-red-500";
            } else if (typeof data.server_health.db_healthy !== 'undefined') {
                // HTTP Format: boolean true/false
                statusText = data.server_health.db_healthy ? "Healthy" : "Error";
                statusClass = data.server_health.db_healthy ? "text-green-400" : "text-red-500";
            }

            dbEl.innerText = statusText;
            dbEl.className = `text-lg font-bold ${statusClass}`;
        }

        // Latency
        const latEl = document.getElementById('dash_latency');
        if (latEl) {
            // Handle WS (int) vs HTTP (string "24ms") mismatch
            let latVal = data.server_health.db_latency || data.server_health.db_latency_ms || 0;
            let latNum = parseInt(latVal);
            
            latEl.innerText = latNum + "ms";
            latEl.className = latNum > 200 ? "text-lg font-bold text-red-500" : 
                              latNum > 100 ? "text-lg font-bold text-yellow-400" : 
                              "text-lg font-bold text-blue-400";
        }
    }

    // C. Security Feed
    if (data.security_feed && Array.isArray(data.security_feed)) {
        renderSecurityFeed(data.security_feed);
    }
}

// --- RENDERERS ---

function renderPendingSellersList(sellers) {
    const container = document.getElementById('dash_seller_list');
    if(!container) return;

    if(sellers.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-500 text-xs py-4">No pending seller requests.</div>`;
        return;
    }

    container.innerHTML = sellers.map(s => {
        const date = new Date(s.created_at);
        const timeAgo = Math.floor((new Date() - date) / (1000 * 60 * 60 * 24));
        const timeText = timeAgo === 0 ? "Today" : `${timeAgo}d ago`;

        return `
        <div class="flex items-center justify-between bg-gray-700/30 p-3 rounded-xl border border-gray-700 hover:bg-gray-700/50 transition">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-xs border border-indigo-500/30">
                    <i class="fas fa-store"></i>
                </div>
                <div>
                    <p class="text-sm font-bold text-gray-200">${s.store_name}</p>
                    <p class="text-[10px] text-gray-400"><i class="far fa-clock mr-1"></i> ${timeText}</p>
                </div>
            </div>
            <button onclick="openSellerReview('${s.seller_id}')" class="text-xs bg-gray-700 hover:bg-white hover:text-gray-900 text-gray-300 px-3 py-1.5 rounded-lg font-bold transition">Review</button>
        </div>
    `}).join('');
}

function renderPendingMenusList(menus) {
    const container = document.getElementById('dash_menu_list');
    if(!container) return;

    if(menus.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-500 text-xs py-6 border-2 border-dashed border-gray-700 rounded-xl">All menus approved!</div>`;
        return;
    }

    container.innerHTML = menus.map(m => {
        const price = formatRupiah(parseFloat(m.price) || 0);
        return `
        <div class="flex items-center justify-between bg-gray-700/30 p-3 rounded-xl border border-gray-700 hover:bg-gray-700/50 transition group">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 rounded-lg bg-orange-500/20 text-orange-400 flex items-center justify-center font-bold text-xs border border-orange-500/30 overflow-hidden">
                    <i class="fas fa-utensils"></i>
                </div>
                <div>
                    <p class="text-sm font-bold text-gray-200 group-hover:text-orange-400 transition">${m.food_name}</p>
                    <p class="text-[10px] text-gray-400">${price}</p>
                </div>
            </div>
            <button onclick="openFoodInspect('${m.food_id}')" class="text-xs bg-orange-600 hover:bg-orange-500 text-white px-3 py-1.5 rounded-lg font-bold transition shadow-lg shadow-orange-500/20">Inspect</button>
        </div>
    `}).join('');
}

function renderSecurityFeed(logs) {
    const container = document.getElementById('dash_security_feed');
    if(!container) return;

    if(logs.length === 0) {
        container.innerHTML = `<div class="text-center text-gray-500 text-xs py-4">System is quiet.</div>`;
        return;
    }

    container.innerHTML = logs.map(log => {
        let icon = 'fa-info-circle text-blue-400';
        let borderColor = 'border-gray-700/50';

        if(log.log_level === 'warning') { icon = 'fa-exclamation-triangle text-orange-400'; borderColor = 'border-orange-500/20'; }
        if(log.log_level === 'error') { icon = 'fa-bug text-red-500'; borderColor = 'border-red-500/20'; }
        if(log.log_action && log.log_action.includes('otp')) icon = 'fa-key text-yellow-400';

        const time = new Date(log.created_at).toLocaleTimeString('id-ID', {hour:'2-digit', minute:'2-digit'});
        
        // ENCODE LOG OBJECT FOR MODAL
        const safeLog = encodeURIComponent(JSON.stringify(log));

        return `
            <div onclick="openLogDetail('${safeLog}')" class="cursor-pointer flex gap-3 text-sm border-b ${borderColor} pb-3 last:border-0 hover:bg-white/5 p-2 rounded transition group">
                <div class="mt-0.5"><i class="fas ${icon}"></i></div>
                <div class="w-full">
                    <p class="text-gray-300 font-medium leading-tight text-xs group-hover:text-white transition">${log.log_message}</p>
                    <div class="flex justify-between mt-1 text-[10px] text-gray-500 font-mono">
                        <span>${log.ip_address || 'IP Hidden'}</span>
                        <span>${time}</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function setText(id, val) {
    const el = document.getElementById(id);
    if(el) el.innerText = val;
}

let currentVerificationId = null;

// 1. OPEN SELLER MODAL
window.openSellerReview = async function(id) {
    currentVerificationId = id;
    openModal('sellerReviewModal');
    
    // Reset / Loading State
    setText('modal_store_name', 'Loading...');
    setText('modal_owner_name', '...');
    
    try {
        const res = await adminFetch(`/admin/pending-sellerprofile/${id}`);
        if(!res.ok) throw new Error("Failed");
        const s = await res.json();

        // Header & Owner
        setText('modal_store_name', s.store_name);
        
        // --- FIX: RATING LOGIC ---
        const ratingContainer = document.getElementById('modal_seller_rating_container');
        if (s.average_rating && s.average_rating > 0) {
            ratingContainer.classList.remove('hidden');
            // Use innerHTML to render the FontAwesome icon
            document.getElementById('modal_seller_rating').innerHTML = `<i class="fas fa-star"></i> ${s.average_rating}`;
            setText('modal_seller_price_range', "$".repeat(s.price_range || 1));
        } else {
            // Hide rating for new sellers
            ratingContainer.classList.add('hidden');
        }

        setText('modal_owner_name', `${s.owner_first_name} ${s.owner_last_name}`);
        setText('modal_owner_email', s.owner_email);

        // Images
        document.getElementById('modal_seller_logo').src = s.logo_url || `https://ui-avatars.com/api/?name=${s.store_name}`;
        document.getElementById('modal_seller_banner').src = s.banner_url || "https://source.unsplash.com/random/800x200/?restaurant";

        // Cuisines Badges
        const cuisineContainer = document.getElementById('modal_seller_cuisines');
        cuisineContainer.innerHTML = (s.cuisine_type || []).map(c => 
            `<span class="text-[10px] font-bold bg-gray-700 text-gray-300 px-2 py-1 rounded border border-gray-600">${c}</span>`
        ).join('');

        // Contact & Location
        setText('modal_seller_phone', s.store_phone_number || '-');
        setText('modal_seller_email', s.store_email || '-');
        const fullAddr = `${s.address_line1}, ${s.address_line2 || ''}, ${s.district}, ${s.city}, ${s.postal_code}`;
        setText('modal_seller_address', fullAddr);
        
        // Map Link
        const mapBtn = document.getElementById('modal_seller_map_btn');
        if (s.latitude && s.longitude) {
            mapBtn.href = `https://www.google.com/maps/search/?api=1&query=${s.latitude},${s.longitude}`;
            mapBtn.classList.remove('hidden');
        } else {
            mapBtn.classList.add('hidden');
        }

        // Description
        setText('modal_seller_desc', s.store_description || 'No description.');

        resetVerificationUI('seller');

    } catch(e) {
        console.error(e);
        alert("Gagal memuat detail seller.");
        closeModal('sellerReviewModal');
    }
};

// 2. OPEN FOOD MODAL
window.openFoodInspect = async function(foodId) {
    if (!foodId) return;

    // 1. Show Modal & Loading
    openModal('foodInspectModal');
    setText('modal_food_name', 'Loading...');
    
    // Reset Image State
    const imgEl = document.getElementById('modal_food_img');
    const noPhotoEl = document.getElementById('modal_food_no_photo');
    if(imgEl) imgEl.classList.add('hidden');
    if(noPhotoEl) noPhotoEl.classList.remove('hidden');

    try {
        // 2. Fetch Data
        const res = await adminFetch(`/admin/food/${foodId}`);
        if(!res.ok) throw new Error("Failed to fetch food details");
        
        const f = await res.json();

        // 3. Populate Basic Info
        setText('modal_food_name', f.food_name || 'Unnamed Food');
        setText('modal_food_price', formatRupiah(f.price || 0));
        setText('modal_food_stock', `Stock: ${f.stock_count ?? 0}`);
        
        // Handle Category (Array or String)
        let cat = 'General';
        if (Array.isArray(f.food_category) && f.food_category.length > 0) {
            cat = f.food_category[0];
        } else if (typeof f.food_category === 'string') {
            cat = f.food_category;
        }
        setText('modal_food_cat', cat);
        
        setText('modal_food_desc', f.description || 'No description provided.');

        // 4. Handle Image
        const photoUrl = f.photo_url || f.thumbnail_url;
        if (photoUrl && imgEl && noPhotoEl) {
            imgEl.src = photoUrl;
            imgEl.classList.remove('hidden');
            noPhotoEl.classList.add('hidden');
        }

        // 5. Populate Tags
        const tagsContainer = document.getElementById('modal_food_tags');
        if (tagsContainer) {
            const tags = Array.isArray(f.tags) ? f.tags : [];
            if (tags.length > 0) {
                tagsContainer.innerHTML = tags.map(t => 
                    `<span class="text-[9px] font-bold uppercase text-gray-400 bg-gray-700/50 px-1.5 py-0.5 rounded border border-gray-700">#${t}</span>`
                ).join('');
            } else {
                tagsContainer.innerHTML = '<span class="text-xs text-gray-600">No tags</span>';
            }
        }

        // 6. Populate Nutrition Facts
        setText('modal_food_serving_size', `${f.serving_size || '-'} (${f.serving_size_grams || 0}g)`);
        
        setText('modal_val_cal', (f.calories || 0) + ' kcal');
        setText('modal_val_pro', (f.protein_grams || 0) + 'g');
        setText('modal_val_carb', (f.carbs_grams || 0) + 'g');
        setText('modal_val_fat', (f.fat_grams || 0) + 'g');
        
        setText('modal_val_fib', (f.fiber_grams || 0) + 'g');
        setText('modal_val_sug', (f.sugar_grams || 0) + 'g');
        setText('modal_val_sod', (f.sodium_mg || 0) + 'mg');
        setText('modal_val_chol', (f.cholesterol_mg || 0) + 'mg');
        
        // Diabetic Specific
        setText('modal_val_gi', f.glycemic_index ?? '-');
        setText('modal_val_gl', f.glycemic_load ?? '-');

        // 7. Update UI Buttons based on approval status
        // If it's the "Pending Food" context, we show approve/reject.
        // If it's just viewing details, we might hide actions.
        // For now, we reset to default view.
        if (document.getElementById('foodActionsDefault')) {
            document.getElementById('foodActionsDefault').classList.remove('hidden');
            document.getElementById('foodActionsReject').classList.add('hidden');
        }

    } catch(e) {
        console.error("Food Detail Error:", e);
        alert("Gagal memuat detail makanan.");
        closeModal('foodInspectModal');
    }
};

// 3. NEW FUNCTION: OPEN LOG DETAIL MODAL
window.openLogDetail = function(encodedLog) {
    const log = JSON.parse(decodeURIComponent(encodedLog));
    
    // Populate Fields
    document.getElementById('log_modal_id').innerText = log.log_id || 'N/A';
    document.getElementById('log_modal_action').innerText = log.log_action || 'System Event';
    document.getElementById('log_modal_message').innerText = log.log_message || '-';
    document.getElementById('log_modal_ip').innerText = log.ip_address || 'Unknown';
    document.getElementById('log_modal_agent').innerText = log.user_agent || 'Unknown';
    document.getElementById('log_modal_user').innerText = log.user_id || 'Guest';
    
    // Format Date
    const date = new Date(log.created_at).toLocaleString('id-ID', { dateStyle: 'full', timeStyle: 'medium' });
    document.getElementById('log_modal_time').innerText = date;

    // Color Coding
    const badge = document.getElementById('log_modal_level');
    badge.innerText = log.log_level.toUpperCase();
    badge.className = "text-[10px] font-bold px-2 py-0.5 rounded border ";
    
    if(log.log_level === 'error') badge.classList.add('bg-red-500/20', 'text-red-400', 'border-red-500/30');
    else if(log.log_level === 'warning') badge.classList.add('bg-orange-500/20', 'text-orange-400', 'border-orange-500/30');
    else badge.classList.add('bg-blue-500/20', 'text-blue-400', 'border-blue-500/30');

    openModal('logDetailModal');
};

// Helper to reset buttons
function resetVerificationUI(type) {
    document.getElementById(`${type}ActionsDefault`).classList.remove('hidden');
    document.getElementById(`${type}ActionsReject`).classList.add('hidden');
    const reasonInput = document.getElementById(`${type}RejectReason`);
    if(reasonInput) reasonInput.value = '';
}

// 3. TOGGLE REJECT INPUT
window.toggleRejectReason = function(type) {
    const def = document.getElementById(`${type}ActionsDefault`);
    const rej = document.getElementById(`${type}ActionsReject`);
    
    if (def.classList.contains('hidden')) {
        def.classList.remove('hidden');
        rej.classList.add('hidden');
    } else {
        def.classList.add('hidden');
        rej.classList.remove('hidden');
    }
};

// 4. SUBMIT ACTION
window.submitVerification = async function(type, action) {
    if (!currentVerificationId) return;

    let endpoint = '';
    let payload = { action: action }; 

    if (type === 'seller') {
        endpoint = `/admin/verify-seller/${currentVerificationId}`;
        if (action === 'reject') {
            payload.reason = document.getElementById('sellerRejectReason').value;
            if (!payload.reason) return alert("Please provide a rejection reason.");
        }
    } else {
        endpoint = `/admin/verify-food/${currentVerificationId}`;
        if (action === 'reject') {
            payload.reason = document.getElementById('foodRejectReason').value;
            if (!payload.reason) return alert("Please provide a rejection reason.");
        }
    }

    try {
        const res = await adminFetch(endpoint, {
            method: 'PUT',
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            alert(`${type === 'seller' ? 'Seller' : 'Menu'} ${action}ed successfully!`);
            closeModal(`${type === 'seller' ? 'sellerReviewModal' : 'foodInspectModal'}`);
            fetchAdminStats(); // Refresh Dashboard List
        } else {
            const err = await res.json();
            alert("Error: " + (err.error || "Action failed"));
        }
    } catch (e) {
        console.error(e);
        alert("Connection error");
    }
};

// =========================================================
//  SECTION: VERIFICATION PAGES LOGIC
// =========================================================

// GLOBAL VARIABLE TO STORE SELLERS
let globalPendingSellers = [];

// --- SELLER REQUESTS PAGE INIT ---
async function initSellerRequestsPage() {
    console.log("Init Seller Requests");
    const grid = document.getElementById('seller_request_grid');
    const countEl = document.getElementById('page_total_count');

    try {
        const res = await adminFetch('/admin/pending-seller');
        if(!res.ok) throw new Error("Failed to load");
        
        // STORE DATA GLOBALLY
        globalPendingSellers = await res.json();
        
        // Initial Render
        renderSellerGrid(globalPendingSellers);

    } catch (e) {
        console.error(e);
        grid.innerHTML = `<div class="col-span-full text-center text-red-400 py-10">Failed to load data.</div>`;
    }
}

// --- FILTER & SORT LOGIC ---
window.filterSellerRequests = function() {
    const search = document.getElementById('sellerSearchInput').value.toLowerCase();
    const sort = document.getElementById('sellerSortSelect').value;

    // 1. Filter by Name
    let filtered = globalPendingSellers.filter(s => 
        s.store_name.toLowerCase().includes(search)
    );

    // 2. Sort
    filtered.sort((a, b) => {
        const dateA = new Date(a.created_at);
        const dateB = new Date(b.created_at);
        
        if (sort === 'newest') return dateB - dateA;
        if (sort === 'oldest') return dateA - dateB;
        if (sort === 'az') return a.store_name.localeCompare(b.store_name);
        return 0;
    });

    renderSellerGrid(filtered);
};

// --- RENDER GRID ---
function renderSellerGrid(sellers) {
    const grid = document.getElementById('seller_request_grid');
    const countEl = document.getElementById('page_total_count');
    
    if(countEl) countEl.innerText = sellers.length;

    if (sellers.length === 0) {
        grid.innerHTML = `<div class="col-span-full text-center text-gray-500 py-20 bg-gray-800/50 rounded-xl border border-dashed border-gray-700">No matching requests found.</div>`;
        return;
    }

    grid.innerHTML = sellers.map(s => {
        const date = new Date(s.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
        
        return `
        <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden shadow-lg hover:border-blue-500/50 transition group flex flex-col animate-fade-in">
            <div class="h-24 bg-gray-700 relative">
                <img src="${s.banner_url || ''}" class="w-full h-full object-cover opacity-50 transition duration-500 group-hover:scale-105">
                <div class="absolute -bottom-6 left-4">
                    <img src="${s.logo_url}" class="w-12 h-12 rounded-lg bg-gray-800 border-2 border-gray-800 object-cover">
                </div>
                <div class="absolute top-3 right-3">
                    <span class="bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 text-[10px] font-bold px-2 py-1 rounded uppercase tracking-wide">Pending</span>
                </div>
            </div>
            
            <div class="p-4 pt-8 flex-1 flex flex-col">
                <h3 class="text-lg font-bold text-white leading-tight mb-1 truncate">${s.store_name}</h3>
                <p class="text-xs text-gray-400 mb-3 truncate"><i class="fas fa-map-marker-alt mr-1"></i> ${s.city || 'Unknown Location'}</p>
                
                <div class="grid grid-cols-2 gap-2 text-[10px] text-gray-400 mb-4 bg-gray-900/50 p-2 rounded-lg border border-gray-700/50">
                    <div>
                        <span class="block font-bold text-gray-500 uppercase">Phone</span>
                        <span class="text-gray-300 font-mono">${s.store_phone_number}</span>
                    </div>
                    <div>
                        <span class="block font-bold text-gray-500 uppercase">Joined</span>
                        <span class="text-gray-300">${date}</span>
                    </div>
                </div>

                <div class="mt-auto">
                    <button onclick="openSellerReview('${s.seller_id}')" class="w-full py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-bold rounded-xl transition shadow-lg shadow-blue-600/20 active:scale-95">
                        Review Application
                    </button>
                </div>
            </div>
        </div>
        `;
    }).join('');
}

// --- MENU REQUESTS PAGE ---
async function initMenuRequestsPage() {
    console.log("Init Menu Requests");
    const grid = document.getElementById('menu_request_grid');
    const countEl = document.getElementById('page_total_count');

    try {
        const res = await adminFetch('/admin/pending-food');
        if(!res.ok) throw new Error("Failed to load");
        
        const foods = await res.json();
        if(countEl) countEl.innerText = foods.length;

        if (foods.length === 0) {
            grid.innerHTML = `<div class="col-span-full text-center text-gray-500 py-20 bg-gray-800/50 rounded-xl border border-dashed border-gray-700">No pending menu items.</div>`;
            return;
        }

        grid.innerHTML = foods.map(f => {
            const price = formatRupiah(f.price);
            const cal = f.calories || 0;
            const img = f.photo_url || f.thumbnail_url;

            return `
            <div class="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden shadow-lg hover:border-orange-500/50 transition flex flex-col">
                <div class="relative h-40 bg-gray-700 group overflow-hidden">
                    ${img ? 
                        `<img src="${img}" class="w-full h-full object-cover group-hover:scale-110 transition duration-500">` : 
                        `<div class="w-full h-full flex items-center justify-center text-gray-600"><i class="fas fa-utensils text-3xl"></i></div>`
                    }
                    <div class="absolute top-2 left-2 bg-black/60 backdrop-blur-md px-2 py-1 rounded text-xs font-bold text-white">
                        ${price}
                    </div>
                </div>

                <div class="p-4 flex-1 flex flex-col">
                    <div class="mb-2">
                        <span class="text-[10px] text-orange-400 font-bold uppercase tracking-wider">${f.store_name || 'Unknown Store'}</span>
                        <h3 class="text-base font-bold text-white leading-snug mt-0.5 line-clamp-1">${f.food_name}</h3>
                    </div>

                    <div class="flex gap-2 mb-4">
                        <span class="px-1.5 py-0.5 bg-gray-700 text-gray-300 text-[10px] rounded font-bold border border-gray-600">${cal} kcal</span>
                        <span class="px-1.5 py-0.5 bg-blue-900/30 text-blue-300 text-[10px] rounded font-bold border border-blue-800/50">GI: ${f.glycemic_index || 0}</span>
                    </div>

                    <div class="mt-auto pt-3 border-t border-gray-700">
                        <button onclick="openFoodInspect('${f.food_id}')" class="w-full py-2 bg-gray-700 hover:bg-orange-600 hover:text-white text-gray-300 text-sm font-bold rounded-lg transition">
                            Inspect
                        </button>
                    </div>
                </div>
            </div>
            `;
        }).join('');

    } catch (e) {
        console.error(e);
        grid.innerHTML = `<div class="col-span-full text-center text-red-400 py-10">Failed to load data.</div>`;
    }
}

// =========================================================
//  SECTION: USER MANAGEMENT
// =========================================================

let globalUsers = [];
let currentUserTargetId = null; 

async function initUserManagement() {
    console.log("Init User Management");
    const tableBody = document.getElementById('user_table_body');

    try {
        const res = await adminFetch('/admin/users');
        if (!res.ok) throw new Error("Failed to load users");
        
        globalUsers = await res.json();
        
        // --- 1. UPDATE STATS ---
        updateUserStats(globalUsers);

        // --- 2. RENDER TABLE ---
        renderUserTable(globalUsers);

    } catch (e) {
        console.error(e);
        if(tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-red-400">Failed to load data.</td></tr>`;
    }
}

// NEW FUNCTION: Calculate stats from the user list
function updateUserStats(users) {
    const total = users.length;
    
    // Count based on status
    const active = users.filter(u => {
        const s = (u.status?.user_status || 'active').toLowerCase();
        return s === 'active';
    }).length;

    const suspended = users.filter(u => {
        const s = (u.status?.user_status || '').toLowerCase();
        return s === 'suspended';
    }).length;

    // Combine Banned & Deactivated into "Restricted"
    const restricted = users.filter(u => {
        const s = (u.status?.user_status || '').toLowerCase();
        return s === 'banned' || s === 'deactivated';
    }).length;

    // Update DOM elements
    setText('u_total_users', total);
    setText('u_active_users', active);
    setText('u_suspended_users', suspended);
    setText('u_banned_users', restricted);
}

function generateRoleBadges(rolesString) {
    if (!rolesString) return '<span class="text-gray-500 text-[10px]">No Role</span>';
    
    // Split "seller, user" -> ["seller", "user"]
    return rolesString.split(',').map(r => {
        const role = r.trim().toLowerCase();
        if (!role) return '';

        let colorClass = "bg-gray-700 text-gray-400 border-gray-600";
        let icon = "";

        if (role === 'seller') {
            colorClass = "bg-purple-500/10 text-purple-400 border-purple-500/20";
            icon = '<i class="fas fa-store mr-1"></i>';
        } else if (role === 'user') {
            colorClass = "bg-blue-500/10 text-blue-400 border-blue-500/20";
            icon = '<i class="fas fa-user mr-1"></i>';
        }

        return `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${colorClass}">${icon}${role}</span>`;
    }).join(' ');
}

function renderUserTable(users) {
    const tbody = document.getElementById('user_table_body');
    if (!tbody) return;

    if (users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="p-8 text-center text-gray-500">No users found.</td></tr>`;
        return;
    }

    tbody.innerHTML = users.map(u => {
        // --- DATA MAPPING ---
        const id = u.user_id;
        const username = u.user_username || 'No Username';
        const email = u.user_email || 'No Email';
        
        // Handle nested status object
        const rawStatus = (u.status && u.status.user_status) ? u.status.user_status : 'active';
        const status = rawStatus.toLowerCase();

        const rawDate = u.created_at;
        const pic = null; // List endpoint doesn't return avatar, use placeholder

        const roleBadges = generateRoleBadges(u.roles);

        // Status Badge Styling
        let statusClass = "bg-gray-700 text-gray-300 border-gray-600";
        if(status === 'active') statusClass = "bg-green-500/10 text-green-400 border-green-500/20";
        if(status === 'suspended') statusClass = "bg-orange-500/10 text-orange-400 border-orange-500/20";
        if(status === 'banned') statusClass = "bg-red-500/10 text-red-400 border-red-500/20";
        if(status === 'deactivated') statusClass = "bg-gray-500/10 text-gray-400 border-gray-500/20";

        const joined = rawDate ? new Date(rawDate).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '-';
        const avatar = `https://ui-avatars.com/api/?name=${username}&background=random`;

        return `
        <tr class="hover:bg-gray-800/50 transition group border-b border-gray-700/50 last:border-0">
            <td class="p-4">
                <div class="flex items-center gap-3">
                    <img src="${avatar}" class="w-10 h-10 rounded-full bg-gray-700 object-cover border border-gray-600">
                    <div>
                        <p class="font-bold text-white text-sm">${username}</p>
                        <p class="text-xs text-gray-400 font-mono">${email}</p>
                    </div>
                </div>
            </td>
            <td class="p-4">
                <div class="flex flex-wrap gap-1">${roleBadges}</div>
            </td>
            <td class="p-4">
                <span class="px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wide border ${statusClass}">
                    ${status}
                </span>
            </td>
            <td class="p-4 text-sm text-gray-400">
                ${joined}
            </td>
            <td class="p-4 text-right">
                <button onclick="openUserDetail('${id}')" class="px-3 py-1.5 bg-gray-700 hover:bg-white hover:text-gray-900 text-gray-300 rounded-lg text-xs font-bold transition shadow-lg">
                    Manage
                </button>
            </td>
        </tr>
        `;
    }).join('');
}

function filterUsers() {
    const search = document.getElementById('userSearchInput').value.toLowerCase();
    const statusFilter = document.getElementById('userStatusFilter').value.toLowerCase();

    const filtered = globalUsers.filter(u => {
        const username = (u.user_username || '').toLowerCase();
        const email = (u.user_email || '').toLowerCase();
        
        // Handle nested status for filter
        const rawStatus = (u.status && u.status.user_status) ? u.status.user_status : 'active';
        const status = rawStatus.toLowerCase();

        const matchesSearch = username.includes(search) || email.includes(search);
        const matchesStatus = statusFilter === 'all' || status === statusFilter;
        
        return matchesSearch && matchesStatus;
    });

    renderUserTable(filtered);
}

// --- USER DETAIL & ACTIONS ---

// 1. Tab Switcher
window.switchUserTab = function(tabName) {
    ['health', 'orders', 'logs'].forEach(t => {
        document.getElementById(`tab_content_${t}`).classList.add('hidden');
        const btn = document.getElementById(`tab_btn_${t}`);
        btn.classList.remove('text-blue-400', 'border-blue-400');
        btn.classList.add('text-gray-500', 'border-transparent');
    });

    document.getElementById(`tab_content_${tabName}`).classList.remove('hidden');
    const activeBtn = document.getElementById(`tab_btn_${tabName}`);
    activeBtn.classList.remove('text-gray-500', 'border-transparent');
    activeBtn.classList.add('text-blue-400', 'border-blue-400');
};

let currentUserLogs = []; // Store logs for filtering

async function openUserDetail(id) {
    if(!id || id === 'undefined') return alert("Invalid User ID.");

    currentUserTargetId = id;
    openModal('userDetailModal');
    switchUserTab('health'); 
    
    // UI Reset
    setText('u_modal_name', 'Loading...');
    setText('u_modal_email', '...');
    document.getElementById('u_safety_grid').innerHTML = '<p class="text-gray-500 text-sm">Loading...</p>';
    document.getElementById('u_orders_list').innerHTML = '';
    document.getElementById('u_logs_list').innerHTML = '';
    
    // Reset Filters
    document.getElementById('log_search').value = '';
    document.getElementById('log_date_start').value = '';
    document.getElementById('log_date_end').value = '';
    currentUserLogs = []; 

    try {
        const res = await adminFetch(`/admin/users/${id}`);
        if(!res.ok) throw new Error("Load failed");
        
        const data = await res.json();
        
        // 1. IDENTITY
        const iden = data.customer_identity;
        if(iden) {
            const fullName = `${iden.user_firstname} ${iden.user_lastname}`;
            setText('u_modal_name', fullName);
            setText('u_modal_email', iden.user_email);
            document.getElementById('u_modal_avatar').src = `https://ui-avatars.com/api/?name=${fullName}&background=random`;
            document.getElementById('u_modal_notes').value = iden.admin_notes || "";

            const status = (iden.status?.user_status || 'active').toUpperCase();
            const statusEl = document.getElementById('u_modal_status');
            statusEl.innerText = status;
            statusEl.className = "px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider border ";
            
            if(status === 'ACTIVE') statusEl.classList.add('bg-green-500/10', 'text-green-400', 'border-green-500/20');
            else if(status === 'BANNED') statusEl.classList.add('bg-red-500/10', 'text-red-400', 'border-red-500/20');
            else statusEl.classList.add('bg-gray-700', 'text-gray-400', 'border-gray-600');

            const verEl = document.getElementById('u_modal_verified');
            if(iden.is_email_verified) verEl?.classList.remove('hidden');
            else verEl?.classList.add('hidden');
        }

        // 2. STATS & SAFETY (Tab 1)
        const stats = data.operational_stats;
        if(stats) {
            setText('u_stat_count', stats.order_count);
            setText('u_stat_rate', stats.success_rate);
            setText('u_stat_spent', formatRupiah(stats.total_spent));
            const relEl = document.getElementById('u_stat_reliable');
            relEl.innerHTML = stats.is_reliable 
                ? '<span class="text-green-400"><i class="fas fa-check"></i> Yes</span>' 
                : '<span class="text-orange-400"><i class="fas fa-exclamation-circle"></i> Low</span>';
        }
        
        const safe = data.safety_flags;
        const safeGrid = document.getElementById('u_safety_grid');
        if(safe && safe.condition_id) {
            safeGrid.innerHTML = `
                <div class="bg-gray-700/30 p-3 rounded-xl border border-gray-700">
                    <p class="text-[10px] font-bold text-gray-500 uppercase">Condition</p>
                    <p class="text-white font-medium text-sm mt-1">Type ${safe.condition_id} Diabetes</p>
                </div>
                <div class="bg-gray-700/30 p-3 rounded-xl border border-gray-700">
                    <p class="text-[10px] font-bold text-gray-500 uppercase">Dietary Pattern</p>
                    <p class="text-white font-medium text-sm mt-1 capitalize">${(safe.dietary_pattern || '-').replace('_', ' ')}</p>
                </div>
                <div class="bg-gray-700/30 p-3 rounded-xl border border-gray-700 col-span-2">
                    <p class="text-[10px] font-bold text-gray-500 uppercase">Allergies & Avoidance</p>
                    <div class="flex flex-wrap gap-2 mt-2">
                        ${(safe.food_allergies || []).map(a => `<span class="bg-red-500/10 text-red-400 px-2 py-0.5 rounded text-xs border border-red-500/20">${a}</span>`).join('')}
                        ${(safe.foods_to_avoid || []).map(a => `<span class="bg-orange-500/10 text-orange-400 px-2 py-0.5 rounded text-xs border border-orange-500/20">Avoid: ${a}</span>`).join('')}
                    </div>
                </div>
            `;
        } else {
            safeGrid.innerHTML = `<div class="col-span-2 text-center py-6 text-gray-500 text-xs bg-gray-700/20 rounded-xl">Health profile incomplete.</div>`;
        }

        // 3. ORDER HISTORY (Tab 2)
        const orders = data.order_history || [];
        const orderList = document.getElementById('u_orders_list');
        if(orders.length > 0) {
            orderList.innerHTML = orders.map(o => {
                const date = new Date(o.created_at).toLocaleDateString();
                const price = formatRupiah(o.total_price);
                const safeOrder = encodeURIComponent(JSON.stringify(o));
                
                let statusColor = 'text-gray-400';
                if(o.order_status === 'Completed') statusColor = 'text-green-400';
                else if(o.order_status.includes('Pending') || o.order_status.includes('Waiting')) statusColor = 'text-orange-400';

                return `
                <tr onclick="openOrderDetail('${safeOrder}')" class="border-b border-gray-700/50 last:border-0 hover:bg-gray-700/50 transition cursor-pointer group">
                    <td class="p-3 font-mono text-xs text-blue-300 group-hover:text-blue-200">#${o.order_id.substring(0,8)}</td>
                    <td class="p-3 text-gray-400 text-xs">${date}</td>
                    <td class="p-3 text-gray-300 text-xs font-bold">${o.seller_name || '-'}</td>
                    <td class="p-3 text-white font-bold text-xs">${price}</td>
                    <td class="p-3 text-right text-xs font-bold ${statusColor}">${o.order_status}</td>
                </tr>`;
            }).join('');
        } else {
            orderList.innerHTML = `<tr><td colspan="5" class="p-8 text-center text-gray-500 text-xs">No orders found.</td></tr>`;
        }

        // 4. FULL AUDIT LOGS (Tab 3) - NEW API FIELD
        // Using 'full_audit_logs' from your latest JSON
        currentUserLogs = data.full_audit_logs || data.recent_activity || [];
        
        // Populate Filter Categories dynamically
        const categories = [...new Set(currentUserLogs.map(l => l.log_category))];
        const catSelect = document.getElementById('log_filter_category');
        catSelect.innerHTML = '<option value="all">All Categories</option>' + 
            categories.map(c => `<option value="${c}">${c.charAt(0).toUpperCase() + c.slice(1)}</option>`).join('');

        renderUserLogs(currentUserLogs);

    } catch(e) {
        console.error(e);
        alert("Error loading details: " + e.message);
        closeModal('userDetailModal');
    }
}

// --- LOG FILTERING LOGIC ---
function renderUserLogs(logs) {
    const list = document.getElementById('u_logs_list');
    
    if(logs.length === 0) {
        list.innerHTML = `<div class="text-center py-8 text-gray-500 text-xs">No matching logs.</div>`;
        return;
    }

    list.innerHTML = logs.map(l => {
        const time = new Date(l.created_at).toLocaleString();
        let icon = 'fa-info-circle text-blue-400';
        if(l.log_level === 'warning') icon = 'fa-exclamation-triangle text-orange-400';
        
        return `
        <div class="flex gap-3 text-xs bg-gray-900/30 p-3 rounded-lg border border-gray-700/50 items-start">
            <div class="mt-0.5"><i class="fas ${icon}"></i></div>
            <div class="flex-1">
                <div class="flex justify-between mb-1">
                    <span class="font-bold text-gray-300">${l.log_action}</span>
                    <span class="text-gray-500 font-mono text-[10px]">${time}</span>
                </div>
                <p class="text-gray-400 leading-tight">${l.log_message}</p>
                <div class="mt-1 flex gap-2">
                    <span class="text-gray-600 font-mono text-[9px] bg-gray-800 px-1 rounded uppercase tracking-wider">${l.log_category}</span>
                    <span class="text-gray-600 font-mono text-[9px]">IP: ${l.ip_address}</span>
                </div>
            </div>
        </div>`;
    }).join('');
}

window.filterUserLogs = function() {
    const search = document.getElementById('log_search').value.toLowerCase();
    const category = document.getElementById('log_filter_category').value;
    const startStr = document.getElementById('log_date_start').value;
    const endStr = document.getElementById('log_date_end').value;

    const filtered = currentUserLogs.filter(l => {
        // Text Match
        const matchesSearch = l.log_message.toLowerCase().includes(search) || l.log_action.toLowerCase().includes(search);
        
        // Category Match
        const matchesCat = category === 'all' || l.log_category === category;
        
        // Date Range Match
        let matchesDate = true;
        if (startStr || endStr) {
            const logDate = new Date(l.created_at);
            logDate.setHours(0,0,0,0); // normalize time

            if (startStr) {
                const startDate = new Date(startStr);
                if (logDate < startDate) matchesDate = false;
            }
            if (endStr) {
                const endDate = new Date(endStr);
                if (logDate > endDate) matchesDate = false;
            }
        }

        return matchesSearch && matchesCat && matchesDate;
    });

    renderUserLogs(filtered);
};

// --- OPEN ORDER DETAIL (NEW) ---
window.openOrderDetail = function(encodedOrder) {
    const o = JSON.parse(decodeURIComponent(encodedOrder));
    openModal('orderDetailModal');

    setText('od_id', o.order_id);
    setText('od_status', o.order_status);
    setText('od_total', formatRupiah(o.total_price));
    setText('od_seller_name', o.seller_name || 'Unknown Seller');
    setText('od_seller_contact', o.seller_contact || '-');
    setText('od_payment', o.payment_status);
    setText('od_date', new Date(o.created_at).toLocaleString());

    // ITEMS LIST
    const itemsList = document.getElementById('od_items_list');
    if (o.items && o.items.length > 0) {
        itemsList.innerHTML = o.items.map(i => `
            <tr class="border-b border-gray-700/50 last:border-0">
                <td class="p-3 text-gray-300 font-bold">${i.food_name}</td>
                <td class="p-3 text-center text-gray-400">x${i.quantity}</td>
                <td class="p-3 text-right text-gray-300">${formatRupiah(i.price_at_purchase)}</td>
            </tr>
        `).join('');
    } else {
        itemsList.innerHTML = `<tr><td colspan="3" class="p-4 text-center text-gray-500">No items detail available.</td></tr>`;
    }
};

// --- ACTIONS ---

// 1. Update Internal Notes
async function saveUserNotes() {
    if(!currentUserTargetId) return;
    const notes = document.getElementById('u_modal_notes').value;
    
    try {
        const res = await adminFetch(`/admin/users/notes/${currentUserTargetId}`, {
            method: 'PUT',
            body: JSON.stringify({ notes: notes })
        });
        
        const data = await res.json();
        
        if(res.ok) alert(data.message || "Notes saved!");
        else alert("Failed: " + (data.error || "Unknown error"));
        
    } catch(e) { console.error(e); alert("Network error"); }
}

// 2. Open Status Modal
function openStatusModal() {
    openModal('userStatusModal');
}

// 3. Submit Status Change
async function submitUserStatus() {
    if(!currentUserTargetId) return;
    const status = document.getElementById('status_select').value;
    const reason = document.getElementById('status_reason').value;

    try {
        const res = await adminFetch(`/admin/users/status/${currentUserTargetId}`, {
            method: 'PUT',
            body: JSON.stringify({ status: status, reason: reason })
        });

        const data = await res.json();

        if(res.ok) {
            alert(data.message);
            closeModal('userStatusModal');
            closeModal('userDetailModal'); // Force close to refresh data
            initUserManagement(); // Refresh table
        } else {
            alert("Error: " + (data.error || "Update failed"));
        }
    } catch(e) { console.error(e); alert("Network error"); }
}

// 4. Force Password Reset
async function confirmPasswordReset() {
    if(!currentUserTargetId) return;
    if(!confirm("Are you sure? This will log the user out and email them a new temporary password.")) return;

    try {
        const res = await adminFetch(`/admin/users/force-reset/${currentUserTargetId}`, { method: 'POST' });
        const data = await res.json();
        
        if(res.ok) {
            alert(data.message);
        } else {
            alert("Error: " + (data.error || "Action failed"));
        }
    } catch(e) { console.error(e); alert("Network error"); }
}

// =========================================================
//  SECTION: ADMIN SELLER MANAGEMENT
// =========================================================

let globalSellersList = [];
let currentSellerMenu = [];

async function initSellerManagement() {
    console.log("Init Seller Management");
    await loadSellersList();
}

async function loadSellersList() {
    const tbody = document.getElementById('sellersMgmtTableBody');
    if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-gray-500">Loading...</td></tr>`;

    try {
        const res = await adminFetch('/admin/sellers');
        if (!res.ok) throw new Error("Failed to fetch");
        
        globalSellersList = await res.json();
        
        updateSellerStats(globalSellersList);
        filterSellersList();

    } catch (error) {
        console.error(error);
        if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-red-400">Error loading data</td></tr>`;
    }
}

function updateSellerStats(sellers) {
    const total = sellers.length;
    const active = sellers.filter(s => (s.admin_status?.seller_admin_status || 'active') === 'active').length;
    const suspended = sellers.filter(s => (s.admin_status?.seller_admin_status) === 'suspended').length;
    const pending = sellers.filter(s => s.verification_status === 'pending').length;

    setText('m_total_sellers', total);
    setText('m_active_sellers', active);
    setText('m_suspended_sellers', suspended);
    setText('m_pending_sellers', pending);
}

window.filterSellersList = function() {
    const search = document.getElementById('sellerMgmtSearch').value.toLowerCase();
    const statusFilter = document.getElementById('sellerMgmtStatusFilter').value;
    const sortVal = document.getElementById('sellerMgmtSort').value;

    let filtered = globalSellersList.filter(s => {
        const matchesSearch = (s.store_name || '').toLowerCase().includes(search) || (s.city || '').toLowerCase().includes(search);
        const status = s.admin_status?.seller_admin_status || 'active';
        const matchesStatus = statusFilter === 'all' || status === statusFilter;
        return matchesSearch && matchesStatus;
    });

    filtered.sort((a, b) => {
        if(sortVal === 'newest') return new Date(b.created_at) - new Date(a.created_at);
        if(sortVal === 'oldest') return new Date(a.created_at) - new Date(b.created_at);
        if(sortVal === 'az') return (a.store_name || '').localeCompare(b.store_name || '');
        return 0;
    });

    renderSellersTable(filtered);
}

function renderSellersTable(sellers) {
    const tbody = document.getElementById('sellersMgmtTableBody');
    const countDisplay = document.getElementById('sellerCountDisplay');
    
    if(countDisplay) countDisplay.innerText = `Showing ${sellers.length} sellers`;
    if(!tbody) return;

    if(sellers.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-gray-500">No sellers found.</td></tr>`;
        return;
    }

    tbody.innerHTML = sellers.map(s => {
        const id = s.seller_id; // Explicit ID extraction
        const status = s.admin_status?.seller_admin_status || 'active';
        
        let statusClass = "bg-green-500/10 text-green-400 border-green-500/20";
        if(status === 'suspended') statusClass = "bg-orange-500/10 text-orange-400 border-orange-500/20";
        if(status === 'blacklisted') statusClass = "bg-red-500/10 text-red-400 border-red-500/20";

        let verifClass = s.verification_status === 'verified' ? 'text-green-400 font-bold' : 'text-gray-500';
        if(s.verification_status === 'pending') verifClass = 'text-yellow-400 font-bold';

        return `
            <tr class="border-b border-gray-700/50 hover:bg-gray-800/50 transition">
                <td class="p-4">
                    <div class="font-bold text-white">${s.store_name || 'Unknown Store'}</div>
                    <div class="text-xs text-gray-500 font-mono">${s.store_slug || '-'}</div>
                </td>
                <td class="p-4 text-gray-300">${s.city || '-'}</td>
                <td class="p-4 text-center text-xs ${verifClass} uppercase tracking-wide">${s.verification_status || '-'}</td>
                <td class="p-4 text-center">
                    <span class="px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide border ${statusClass}">${status}</span>
                </td>
                <td class="p-4 text-center text-sm text-gray-400">${s.created_at ? new Date(s.created_at).toLocaleDateString() : '-'}</td>
                <td class="p-4 text-right">
                    <div class="flex items-center justify-end gap-2">
                        <button onclick="viewSellerDetail('${id}')" class="bg-blue-600 hover:bg-blue-500 text-white p-2 rounded-lg transition" title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button onclick="viewSellerReviews('${id}')" class="bg-purple-600 hover:bg-purple-500 text-white p-2 rounded-lg transition" title="Reviews">
                            <i class="fas fa-comment-dots"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// --- SELLER DETAIL MODAL LOGIC ---

window.viewSellerDetail = async function(sellerId) {
    if (!sellerId) { console.error("Missing Seller ID"); return; }

    try {
        // 1. Fetch Full Details
        const res = await adminFetch(`/admin/seller/${sellerId}`);
        if(!res.ok) throw new Error("Fetch failed");
        
        const data = await res.json();
        const p = data.profile?.details || {}; // Handle nested profile
        const stats = data.statistics || {};
        const orders = data.order_history || [];

        // 2. Reset UI State
        currentSellerMenu = []; // Clear old menu
        document.getElementById('sellerMenuGrid').innerHTML = '';
        document.getElementById('menuSearch').value = '';
        switchSellerTab('overview'); // Default Tab
        
        // 3. Populate Header & Basic Info
        document.getElementById('detailSellerId').value = p.seller_id;
        document.getElementById('detailStoreNameHeader').innerText = p.store_name || 'Unknown Store';
        document.getElementById('detailOwnerNameHeader').innerText = p.user_id ? 'User ID: ' + p.user_id.substring(0,8) : 'Unknown Owner';

        // Overview Tab Fields
        document.getElementById('detailStoreName').innerText = p.store_name || '-';
        document.getElementById('detailOwnerName').innerText = p.user_id || '-';
        document.getElementById('detailPhone').innerText = p.store_phone_number || '-';
        document.getElementById('detailEmail').innerText = p.store_email || '-';
        document.getElementById('detailAddress').innerText = `${p.address_line1 || ''}, ${p.city || ''}`;
        
        // Populate Stats
        document.getElementById('statTotalRev').innerText = formatRupiah(stats.total_revenue || 0);
        document.getElementById('statTotalOrd').innerText = stats.total_orders || 0;
        document.getElementById('statMonthRev').innerText = formatRupiah(stats.this_month_revenue || 0);
        document.getElementById('statMonthOrd').innerText = stats.this_month_orders || 0;

        // Admin Actions Form
        const adminStatus = p.admin_status?.seller_admin_status || 'active';
        const statusSelect = document.getElementById('detailAdminStatus');
        if(statusSelect) statusSelect.value = adminStatus;
        
        const notesInput = document.getElementById('detailAdminNotes');
        if(notesInput) notesInput.value = p.admin_notes || '';

        // Render Business Hours
        const hoursContainer = document.getElementById('detailBusinessHours');
        if(hoursContainer) {
            hoursContainer.innerHTML = '';
            let bHours = p.business_hours;
            
            // Handle if it's a JSON string
            if (typeof bHours === 'string') { try { bHours = JSON.parse(bHours); } catch(e){} }
            // Handle if it's base64 encoded JSON (common in JWT/DB)
            if (typeof bHours === 'string') { try { bHours = JSON.parse(atob(bHours)); } catch(e){} }

            if (bHours && typeof bHours === 'object') {
                Object.entries(bHours).forEach(([day, times]) => {
                    if(!times) return;
                    const text = times.closed ? `<span class="text-red-400 font-bold">Closed</span>` : `<span class="text-white">${times.open} - ${times.close}</span>`;
                    hoursContainer.innerHTML += `<div class="bg-gray-900/50 p-2 rounded border border-gray-700/50"><div class="capitalize text-xs font-bold text-gray-500 mb-1">${day}</div>${text}</div>`;
                });
            } else {
                hoursContainer.innerHTML = '<span class="text-gray-500 text-xs col-span-full">No hours set.</span>';
            }
        }

        // 4. Populate Order History Tab
        const orderBody = document.getElementById('detailOrderTableBody');
        if(orderBody) {
            orderBody.innerHTML = '';
            if(orders.length === 0) {
                orderBody.innerHTML = '<tr><td colspan="5" class="p-4 text-center text-gray-500">No orders found.</td></tr>';
            } else {
                orders.slice(0, 10).forEach(o => { 
                    orderBody.innerHTML += `
                        <tr class="border-b border-gray-700/50 last:border-0 hover:bg-gray-700/30">
                            <td class="p-3 font-mono text-xs text-blue-300">#${(o.order_id || '').substring(0,8)}</td>
                            <td class="p-3 text-gray-300">${o.user_firstname} ${o.user_lastname}</td>
                            <td class="p-3 text-green-400 font-bold">${formatRupiah(o.total_price)}</td>
                            <td class="p-3 text-xs text-gray-400">${o.status}</td>
                            <td class="p-3 text-xs text-gray-500">${new Date(o.created_at).toLocaleDateString()}</td>
                        </tr>
                    `;
                });
            }
        }

        openModal('sellerDetailModal');

    } catch (e) {
        console.error("View Detail Error:", e);
        alert("Failed to load seller details.");
    }
}

// --- TABS & MENU LOADING ---

window.switchSellerTab = function(tab) {
    // 1. Update UI Tabs
    ['overview', 'menu', 'orders'].forEach(t => {
        const btn = document.getElementById(`tab_s_${t}`);
        const content = document.getElementById(`content_s_${t}`);
        
        if (t === tab) {
            if(btn) {
                btn.classList.add('border-blue-500', 'text-blue-400');
                btn.classList.remove('border-transparent', 'text-gray-400');
            }
            if(content) content.classList.remove('hidden');
        } else {
            if(btn) {
                btn.classList.remove('border-blue-500', 'text-blue-400');
                btn.classList.add('border-transparent', 'text-gray-400');
            }
            if(content) content.classList.add('hidden');
        }
    });

    // 2. Lazy Load Menu Logic
    if (tab === 'menu' && currentSellerMenu.length === 0) {
        const sellerId = document.getElementById('detailSellerId').value;
        if(sellerId) loadSellerMenu(sellerId);
    }
};

async function loadSellerMenu(sellerId) {
    if (!sellerId || sellerId === 'undefined') {
        console.error("loadSellerMenu called with invalid ID");
        return; 
    }

    const grid = document.getElementById('sellerMenuGrid');
    if(!grid) return;
    
    grid.innerHTML = `<div class="col-span-full text-center py-10"><i class="fas fa-circle-notch fa-spin text-blue-500"></i> Loading menu...</div>`;

    try {
        const res = await adminFetch(`/admin/seller/menu/${sellerId}`);
        if(!res.ok) throw new Error(`HTTP Error ${res.status}`);
        
        const rawData = await res.json();
        console.log("Menu Data:", rawData); // For debugging

        // --- KEY FIX: Detect if data is Array or Object wrapped ---
        let items = [];
        if (Array.isArray(rawData)) {
            items = rawData;
        } else if (rawData && typeof rawData === 'object') {
            // Check common wrapper property names
            if (Array.isArray(rawData.data)) items = rawData.data;
            else if (Array.isArray(rawData.foods)) items = rawData.foods;
            else if (Array.isArray(rawData.menu)) items = rawData.menu;
            else if (Array.isArray(rawData.items)) items = rawData.items;
        }
        
        currentSellerMenu = items;
        renderSellerMenu(currentSellerMenu);

    } catch(e) {
        console.error("Menu Load Error:", e);
        // Show actual error message on UI
        grid.innerHTML = `<div class="col-span-full text-center py-10 text-red-400 text-xs">
            Failed to load menu.<br>
            <span class="text-gray-500">${e.message}</span>
        </div>`;
    }
}

function renderSellerMenu(items) {
    const grid = document.getElementById('sellerMenuGrid');
    if (!grid) return;

    if (!items || items.length === 0) {
        grid.innerHTML = `<div class="col-span-full text-center text-gray-500 text-xs py-20 bg-gray-800/50 rounded-xl border border-gray-700 border-dashed">No menu items found.</div>`;
        return;
    }

    grid.innerHTML = items.map(item => {
        const img = item.photo_url || item.thumbnail_url;
        let statusBadge = '';
        
        if (item.is_approved === 'pending') {
            statusBadge = `<span class="text-[9px] font-bold text-yellow-400 bg-yellow-900/30 px-1.5 py-0.5 rounded border border-yellow-700 uppercase">Pending</span>`;
        } else if (!item.is_active) {
            statusBadge = `<span class="text-[9px] font-bold text-red-400 bg-red-900/30 px-1.5 py-0.5 rounded border border-red-700 uppercase">Inactive</span>`;
        } else {
            statusBadge = `<span class="text-[9px] font-bold text-green-400 bg-green-900/30 px-1.5 py-0.5 rounded border border-green-700 uppercase">Active</span>`;
        }

        return `
        <div class="flex gap-3 bg-gray-800 p-3 rounded-xl border border-gray-700 hover:border-gray-600 transition h-24">
            <div class="w-16 h-16 rounded-lg bg-gray-700 overflow-hidden flex-shrink-0 relative">
                ${img ? `<img src="${img}" class="w-full h-full object-cover">` : `<div class="w-full h-full flex items-center justify-center text-gray-600"><i class="fas fa-utensils"></i></div>`}
            </div>
            <div class="flex-1 min-w-0 flex flex-col justify-between">
                <div>
                    <div class="flex justify-between items-start">
                        <h4 class="font-bold text-white text-sm truncate pr-2" title="${item.food_name}">${item.food_name}</h4>
                        ${statusBadge}
                    </div>
                    <p class="text-xs text-blue-400 font-bold mt-0.5">${formatRupiah(item.price)}</p>
                </div>
                <div class="flex justify-between items-end text-[10px] text-gray-500">
                    <span>Stock: ${item.stock_count === -1 ? '∞' : item.stock_count}</span>
                    <button onclick="openFoodInspect('${item.food_id}')" class="text-xs text-gray-400 hover:text-white transition"><i class="fas fa-eye"></i></button>
                </div>
            </div>
        </div>
        `;
    }).join('');
}

window.filterSellerMenu = function() {
    const term = document.getElementById('menuSearch').value.toLowerCase();
    const filtered = currentSellerMenu.filter(i => (i.food_name || '').toLowerCase().includes(term));
    renderSellerMenu(filtered);
}

// --- ADMIN ACTIONS (Update Status / Notes) ---

window.updateSellerStatus = async function() {
    const sellerId = document.getElementById('detailSellerId').value;
    const status = document.getElementById('detailAdminStatus').value;
    const reason = document.getElementById('detailStatusReason').value;

    if(status !== 'active' && !reason) {
        alert("Please provide a reason for suspension/blacklisting.");
        return;
    }

    try {
        const res = await adminFetch(`/admin/seller/status/${sellerId}`, {
            method: 'PUT',
            body: JSON.stringify({ status, reason })
        });
        
        if(res.ok) {
            alert("Status updated successfully");
            loadSellersList(); // Refresh main list
        } else {
            alert("Failed to update status");
        }
    } catch(e) { console.error(e); }
}

window.updateSellerNotes = async function() {
    const sellerId = document.getElementById('detailSellerId').value;
    const notes = document.getElementById('detailAdminNotes').value;

    try {
        const res = await adminFetch(`/admin/seller/notes/${sellerId}`, {
            method: 'PUT',
            body: JSON.stringify({ notes })
        });
        
        if(res.ok) alert("Notes saved");
        else alert("Failed to save notes");
    } catch(e) { console.error(e); }
}

// --- REVIEWS LOGIC ---

window.viewSellerReviews = async function(sellerId) {
    try {
        const res = await adminFetch(`/admin/seller/reviews/${sellerId}`);
        if(!res.ok) throw new Error("Fetch failed");
        
        const responseData = await res.json();
        const reviews = responseData || []; 

        const container = document.getElementById('reviewsContainer');
        if(container) {
            container.innerHTML = '';

            if(reviews.length === 0) {
                container.innerHTML = `
                    <div class="flex flex-col items-center justify-center h-full py-12 text-gray-500">
                        <div class="bg-gray-700/30 p-4 rounded-full mb-3 border border-gray-600">
                            <i class="fas fa-comment-slash text-2xl text-gray-400"></i>
                        </div>
                        <p class="text-sm font-bold text-gray-300">No reviews yet</p>
                        <p class="text-xs text-gray-500 mt-1">This seller hasn't received any feedback.</p>
                    </div>
                `;
            } else {
                reviews.forEach(r => {
                    let stars = '';
                    const rating = r.rating || 0;
                    for(let i=0; i<5; i++) {
                        stars += `<i class="fas fa-star ${i < rating ? 'text-yellow-400' : 'text-gray-600'} text-xs"></i>`;
                    }

                    container.innerHTML += `
                        <div id="review-${r.review_id}" class="border border-gray-700 bg-gray-900/50 rounded-xl p-4 flex justify-between items-start animate-fade-in mb-3 last:mb-0">
                            <div class="flex-1">
                                <div class="flex items-center gap-2 mb-1">
                                    <span class="font-bold text-sm text-gray-200">${r.user_firstname || 'User'} ${r.user_lastname || ''}</span>
                                    <span class="text-xs text-gray-500">(${r.created_at ? new Date(r.created_at).toLocaleDateString() : 'N/A'})</span>
                                </div>
                                <div class="mb-2">${stars}</div>
                                <p class="text-gray-300 text-sm italic">"${r.review_text || ''}"</p>
                                ${r.seller_reply ? `<div class="mt-3 text-xs text-blue-400 pl-3 border-l-2 border-blue-500/30"><strong>Store Reply:</strong> ${r.seller_reply}</div>` : ''}
                            </div>
                            <button onclick="deleteReview('${r.review_id}')" class="text-gray-500 hover:text-red-500 transition ml-3 bg-gray-800 hover:bg-gray-700 p-2 rounded-lg" title="Delete Review">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    `;
                });
            }
        }
        openModal('sellerReviewsModal');

    } catch(e) { 
        console.error("Review Load Error:", e);
        alert("Failed to load reviews. See console for details.");
    }
}

window.deleteReview = async function(reviewId) {
    if(!confirm("Are you sure you want to delete this review?")) return;

    try {
        const res = await adminFetch(`/admin/seller/reviews/${reviewId}`, { method: 'DELETE' });
        if(res.ok) {
            const el = document.getElementById(`review-${reviewId}`);
            if(el) el.remove();
        } else {
            alert("Failed to delete review");
        }
    } catch(e) { console.error(e); }
}

// =========================================================
//  SECTION: ADMIN FOOD DATABASE LOGIC
// =========================================================

let globalFoodDb = [];

async function initFoodDatabase() {
    console.log("Init Food Database");
    // Set title if header exists
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'Food Database';
    
    await loadFoodDatabase();
}

function updateFoodStats(foods) {
    document.getElementById('f_total_items').innerText = foods.length;
    document.getElementById('f_visible_items').innerText = foods.filter(f => f.is_active).length;
    document.getElementById('f_hidden_items').innerText = foods.filter(f => !f.is_active).length;
    document.getElementById('f_pending_items').innerText = foods.filter(f => f.is_approved === 'pending').length;
}

async function loadFoodDatabase() {
    const tbody = document.getElementById('foodDbTableBody');
    if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-10 text-center text-gray-500"><i class="fas fa-circle-notch fa-spin text-2xl mb-2"></i><br>Loading Database...</td></tr>`;

    try {
        // CALL GET /foods
        const res = await adminFetch('/admin/foods');
        if (!res.ok) throw new Error("Failed to fetch foods");

        globalFoodDb = await res.json();
        
        // Initial Render
        filterFoodDatabase();
        updateFoodStats(globalFoodDb);

    } catch (e) {
        console.error("Food DB Error:", e);
        if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-10 text-center text-red-400">Failed to load data. <br><button onclick="loadFoodDatabase()" class="mt-2 text-white underline">Retry</button></td></tr>`;
    }
}

// --- FILTERING ---
window.filterFoodDatabase = function() {
    const search = document.getElementById('foodDbSearch').value.toLowerCase();
    const statusFilter = document.getElementById('foodDbStatusFilter').value;
    const visFilter = document.getElementById('foodDbVisibilityFilter').value;

    const filtered = globalFoodDb.filter(f => {
        // 1. Search (Name, Store, ID)
        const matchSearch = f.food_name.toLowerCase().includes(search) || 
                            f.store_name.toLowerCase().includes(search) ||
                            f.food_id.includes(search);
        
        // 2. Status Filter
        const matchStatus = statusFilter === 'all' || f.is_approved === statusFilter;

        // 3. Visibility Filter
        let matchVis = true;
        if (visFilter === 'active') matchVis = f.is_active === true;
        if (visFilter === 'inactive') matchVis = f.is_active === false;

        return matchSearch && matchStatus && matchVis;
    });

    renderFoodDatabaseTable(filtered);
};

// --- RENDERING ---
function renderFoodDatabaseTable(foods) {
    const tbody = document.getElementById('foodDbTableBody');
    const countEl = document.getElementById('foodDbCount');
    
    const countSimple = document.getElementById('foodDbCountSimple');
    if (countSimple) countSimple.innerText = foods.length;

    if(countEl) countEl.innerText = `Showing ${foods.length} items`;
    if(!tbody) return;

    if (foods.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-10 text-center text-gray-500 border-dashed border-t border-gray-700">No items found matching filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = foods.map(f => {
        // Nutrition Badge (Carbs / Sugar / Fiber)
        const nutrition = `
            <div class="flex justify-center gap-1">
                <span class="px-1.5 py-0.5 bg-gray-700 text-gray-300 text-[10px] rounded border border-gray-600" title="Carbs">${f.carbs_grams}c</span>
                <span class="px-1.5 py-0.5 bg-gray-700 text-gray-300 text-[10px] rounded border border-gray-600" title="Sugar">${f.sugar_grams}s</span>
                <span class="px-1.5 py-0.5 bg-gray-700 text-gray-300 text-[10px] rounded border border-gray-600" title="Fiber">${f.fiber_grams}f</span>
            </div>
        `;

        // Approval Badge
        let appBadge = `<span class="bg-gray-700 text-gray-400 px-2 py-1 rounded text-[10px] font-bold uppercase">Unknown</span>`;
        if (f.is_approved === 'verified') appBadge = `<span class="bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-1 rounded text-[10px] font-bold uppercase">Verified</span>`;
        if (f.is_approved === 'pending') appBadge = `<span class="bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 px-2 py-1 rounded text-[10px] font-bold uppercase">Pending</span>`;
        if (f.is_approved === 'rejected') appBadge = `<span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-1 rounded text-[10px] font-bold uppercase">Rejected</span>`;

        // Toggle Switch Logic
        const toggleId = `toggle_vis_${f.food_id}`;
        const toggle = `
            <label for="${toggleId}" class="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" id="${toggleId}" class="sr-only peer" onchange="toggleFoodVisibility('${f.food_id}', this)" ${f.is_active ? 'checked' : ''}>
                <div class="w-9 h-5 bg-gray-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600"></div>
                <span class="ml-2 text-xs font-medium text-gray-400 hidden md:block">${f.is_active ? 'Visible' : 'Hidden'}</span>
            </label>
        `;

        return `
            <tr class="hover:bg-gray-800/50 transition group border-b border-gray-700/50 last:border-0">
                <td class="px-6 py-4">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-lg bg-gray-700 flex items-center justify-center text-gray-500 overflow-hidden">
                            <i class="fas fa-utensils"></i>
                        </div>
                        <div>
                            <div class="font-bold text-white text-sm leading-tight">${f.food_name}</div>
                            <div class="text-[10px] text-gray-500 font-mono mt-0.5">ID: ${f.food_id.substring(0,8)}...</div>
                        </div>
                    </div>
                </td>
                <td class="px-6 py-4">
                    <div class="font-medium text-gray-300 text-sm">${f.store_name}</div>
                    <button onclick="viewSellerDetail('${f.seller_id}')" class="text-[10px] text-blue-400 hover:text-blue-300 hover:underline">View Store</button>
                </td>
                <td class="px-6 py-4 text-center">
                    ${nutrition}
                    <div class="text-[10px] text-gray-500 mt-1">GL: ${f.glycemic_load}</div>
                </td>
                <td class="px-6 py-4 text-center">
                    ${appBadge}
                </td>
                <td class="px-6 py-4 text-center">
                    ${toggle}
                </td>
                <td class="px-6 py-4 text-right">
                    <div class="flex items-center justify-end gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition">
                        <button onclick="inspectDatabaseFood('${f.food_id}')" class="p-2 bg-gray-700 hover:bg-blue-600 text-white rounded-lg transition" title="Inspect Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button onclick="deleteDatabaseFood('${f.food_id}')" class="p-2 bg-gray-700 hover:bg-red-600 text-white rounded-lg transition" title="Delete Permanently">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

// --- ACTIONS ---

// 1. Toggle Visibility (PUT)
window.toggleFoodVisibility = async function(foodId, checkbox) {
    const isActive = checkbox.checked;
    const labelSpan = checkbox.nextElementSibling.nextElementSibling; // The text span

    // Optimistic UI Update
    if(labelSpan) labelSpan.innerText = isActive ? 'Visible' : 'Hidden';

    try {
        const res = await adminFetch(`/admin/food/visibility/${foodId}`, {
            method: 'PUT',
            body: JSON.stringify({ is_active: isActive })
        });

        if(!res.ok) throw new Error("API Failed");
        
        // Update local state so filtering still works
        const item = globalFoodDb.find(f => f.food_id === foodId);
        if(item) item.is_active = isActive;

    } catch(e) {
        console.error(e);
        alert("Failed to update visibility.");
        checkbox.checked = !isActive; // Revert
        if(labelSpan) labelSpan.innerText = !isActive ? 'Visible' : 'Hidden';
    }
};

// 2. Delete Food (DELETE)
window.deleteDatabaseFood = async function(foodId) {
    if(!confirm("DANGER: This will permanently delete this food item from the database. This action cannot be undone. Are you sure?")) return;

    try {
        const res = await adminFetch(`/admin/food/${foodId}`, {
            method: 'DELETE'
        });

        if(res.ok) {
            // Remove from local array
            globalFoodDb = globalFoodDb.filter(f => f.food_id !== foodId);
            filterFoodDatabase(); // Re-render
            alert("Food item deleted successfully.");
        } else {
            alert("Failed to delete food item.");
        }
    } catch(e) {
        console.error(e);
        alert("Network Error");
    }
};

// 3. Inspect Details (Reuses existing modal structure but fetches specific endpoint)
window.inspectDatabaseFood = async function(foodId) {
    // We can reuse openFoodInspect logic but we need to fetch from the GENERAL endpoint, not the pending one.
    // Since openFoodInspect calls `/admin/pending-food/`, let's create a specific fetcher here
    // that populates the SAME modal ID 'foodInspectModal'.

    openModal('foodInspectModal');
    setText('modal_food_name', 'Loading...');

    // Hide Approve/Reject buttons for Database view, or keep them? 
    // Usually DB view is for observation. Let's hide the verification buttons to avoid confusion, 
    // OR create a generic "Close" button.
    document.getElementById('foodActionsDefault').classList.add('hidden'); 
    document.getElementById('foodActionsReject').classList.add('hidden');
    // Add a simple close button if not exists (or rely on X button)

    try {
        // CALL GET /food/:id
        const res = await adminFetch(`/admin/food/${foodId}`);
        if(!res.ok) throw new Error("Failed");
        const f = await res.json();

        // Populate Modal (Same mapping as openFoodInspect)
        setText('modal_food_name', f.food_name);
        setText('modal_food_price', formatRupiah(f.price));
        setText('modal_food_stock', `Stock: ${f.stock_count}`);
        setText('modal_food_cat', (f.food_category || ['General'])[0]);
        setText('modal_food_desc', f.description || 'No description.');

        // Photo
        const imgEl = document.getElementById('modal_food_img');
        const noPhotoEl = document.getElementById('modal_food_no_photo');
        const photoUrl = f.photo_url || f.thumbnail_url;
        if (photoUrl) {
            imgEl.src = photoUrl;
            imgEl.classList.remove('hidden');
            noPhotoEl.classList.add('hidden');
        } else {
            imgEl.classList.add('hidden');
            noPhotoEl.classList.remove('hidden');
        }

        // Tags
        const tagsContainer = document.getElementById('modal_food_tags');
        tagsContainer.innerHTML = (f.tags || []).map(t => 
            `<span class="text-[9px] font-bold uppercase text-gray-400 bg-gray-700/50 px-1.5 py-0.5 rounded border border-gray-700">#${t}</span>`
        ).join('');

        // Nutrition
        setText('modal_food_serving_size', `${f.serving_size || '1 srv'} (${f.serving_size_grams || '-'}g)`);
        setText('modal_val_cal', (f.calories || 0) + ' kcal');
        setText('modal_val_pro', (f.protein_grams || 0) + 'g');
        setText('modal_val_carb', (f.carbs_grams || 0) + 'g');
        setText('modal_val_fat', (f.fat_grams || 0) + 'g');
        setText('modal_val_fib', (f.fiber_grams || 0) + 'g');
        setText('modal_val_sug', (f.sugar_grams || 0) + 'g');
        setText('modal_val_sod', (f.sodium_mg || 0) + 'mg');
        setText('modal_val_chol', (f.cholesterol_mg || 0) + 'mg');
        setText('modal_val_gi', f.glycemic_index || 0);
        setText('modal_val_gl', f.glycemic_load || 0);

    } catch(e) {
        console.error(e);
        alert("Failed to load details");
        closeModal('foodInspectModal');
    }
};

// =========================================================
//  SECTION: AI ANALYTICS LOGIC
// =========================================================

let aiUsageChart = null;
let aiFeedbackChart = null;
let globalAISessions = [];

// Helper specifically for AI section to prevent scope issues
function setAIText(id, val) {
    const el = document.getElementById(id);
    if(el) el.innerText = (val !== null && val !== undefined) ? val : '-';
}

async function initAIPage() {
    console.log("Init AI Analytics");
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'AI Analytics';

    await Promise.all([
        loadAIDashboard(),
        loadAISessionsTable()
    ]);
}

async function loadAIDashboard() {
    try {
        const res = await adminFetch('/admin/ai/dashboard');
        if(!res.ok) throw new Error("Failed to load dashboard");
        
        const data = await res.json();
        console.log("AI Dashboard Data:", data);

        // 1. POPULATE KPIs
        setAIText('ai_stat_sessions', data.total_sessions || 0);
        
        const conf = data.avg_confidence ? (data.avg_confidence * 100).toFixed(1) + '%' : '0%';
        setAIText('ai_stat_confidence', conf);

        const help = data.helpfulness_rate ? (data.helpfulness_rate * 100).toFixed(1) + '%' : '0%';
        setAIText('ai_stat_helpful', help);
        
        // Calculate Peak
        const usageData = data.charts?.usage_line_chart || [];
        const peak = usageData.reduce((max, item) => Math.max(max, item.total_requests), 0);
        setAIText('ai_stat_peak', peak);

        // 2. RENDER CHARTS
        if (data.charts) {
            renderAICharts(data.charts);
        }

    } catch(e) {
        console.error("AI Dashboard Error:", e);
    }
}

async function loadAISessionsTable() {
    const tbody = document.getElementById('aiSessionsTableBody');
    if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-gray-500"><i class="fas fa-circle-notch fa-spin"></i> Loading...</td></tr>`;

    try {
        const res = await adminFetch('/admin/ai/sessions'); 
        if(!res.ok) throw new Error("Failed to load sessions list");
        
        const responseData = await res.json();
        
        // FIX: Access the nested 'sessions' array
        globalAISessions = responseData.sessions || []; 
        
        renderAISessionsTable(globalAISessions);

    } catch(e) {
        console.error("Session List Error:", e);
        if(tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-red-400">Failed to load data.</td></tr>`;
    }
}

function renderAISessionsTable(sessions) {
    const tbody = document.getElementById('aiSessionsTableBody');
    const countEl = document.getElementById('aiSessionCount');
    
    if(countEl) countEl.innerText = `Showing ${sessions.length} sessions`;
    if(!tbody) return;

    if(!sessions || sessions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-8 text-center text-gray-500">No sessions found.</td></tr>`;
        return;
    }

    tbody.innerHTML = sessions.map(s => {
        const conf = s.ai_confidence_score || 0;
        let confColor = 'text-red-400 border-red-500/20 bg-red-500/10';
        if(conf >= 0.8) confColor = 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10';
        else if(conf >= 0.5) confColor = 'text-yellow-400 border-yellow-500/20 bg-yellow-500/10';

        const date = new Date(s.created_at).toLocaleString('id-ID');
        const types = (s.requested_types || []).map(t => `<span class="bg-gray-700 text-gray-300 text-[10px] px-1.5 py-0.5 rounded uppercase border border-gray-600">${t}</span>`).join(' ');

        return `
        <tr class="border-b border-gray-700/50 hover:bg-gray-800/50 transition">
            <td class="p-4">
                <div class="font-bold text-white text-sm">${s.user_firstname} ${s.user_lastname}</div>
                <div class="text-xs text-gray-500 font-mono mt-0.5">${s.session_id.substring(0,8)}...</div>
            </td>
            <td class="p-4 text-center"><div class="flex flex-wrap justify-center gap-1">${types}</div></td>
            <td class="p-4 text-center"><span class="text-xs text-gray-400 bg-gray-800 px-2 py-1 rounded border border-gray-700 font-mono">${s.ai_model_used || '?'}</span></td>
            <td class="p-4 text-center"><span class="text-xs font-bold px-2 py-1 rounded border ${confColor}">${(conf * 100).toFixed(0)}%</span></td>
            <td class="p-4 text-center text-xs text-gray-400">${date}</td>
            <td class="p-4 text-right">
                <button onclick="openAISessionDetail('${s.session_id}')" class="bg-indigo-600 hover:bg-indigo-500 text-white p-2 rounded-lg shadow-lg shadow-indigo-500/20"><i class="fas fa-search-plus"></i></button>
            </td>
        </tr>`;
    }).join('');
}

window.filterAISessions = function() {
    const search = document.getElementById('aiSessionSearch').value.toLowerCase();
    const filtered = globalAISessions.filter(s => 
        (s.user_email || '').toLowerCase().includes(search) || 
        (s.session_id || '').toLowerCase().includes(search)
    );
    renderAISessionsTable(filtered);
}

window.openAISessionDetail = async function(sessionId) {
    openModal('aiSessionModal');
    setAIText('ai_modal_response', "Loading detailed analysis...");
    
    try {
        const res = await adminFetch(`/admin/ai/sessions/${sessionId}`);
        if(!res.ok) throw new Error("Failed");
        const data = await res.json();
        
        const meta = data.session_metadata;
        const recs = data.recommendations;

        setAIText('ai_modal_session_id', `Session ID: ${meta.session_id}`);
        setAIText('ai_modal_username', `${meta.user_firstname} ${meta.user_lastname}`);
        setAIText('ai_modal_email', meta.user_email);
        document.getElementById('ai_modal_avatar').src = `https://ui-avatars.com/api/?name=${meta.user_firstname}+${meta.user_lastname}&background=random`;
        
        setAIText('ai_modal_model', meta.ai_model_used);
        setAIText('ai_modal_glucose', meta.latest_glucose_value);
        setAIText('ai_modal_hba1c', meta.latest_hba1c ? meta.latest_hba1c + '%' : '-');

        const confPct = ((meta.ai_confidence_score || 0) * 100).toFixed(1) + '%';
        document.getElementById('ai_modal_confidence_bar').style.width = confPct;
        setAIText('ai_modal_confidence_text', confPct);

        setAIText('ai_modal_response', meta.insights_response || meta.analysis_summary || "No textual analysis.");

        // Foods
        const foodList = document.getElementById('ai_modal_foods_list');
        foodList.innerHTML = (recs.foods || []).map(f => `
            <div class="bg-gray-800 p-3 rounded-xl border border-gray-700 flex gap-3">
                <div class="w-8 h-8 rounded-lg bg-green-500/20 text-green-400 flex items-center justify-center font-bold text-xs shrink-0"><i class="fas fa-apple-alt"></i></div>
                <div><h5 class="text-sm font-bold text-white">${f.food_name}</h5><p class="text-xs text-gray-400 mt-1 line-clamp-2">${f.reason}</p></div>
            </div>`).join('') || '<p class="text-gray-500 text-xs italic">No foods.</p>';

        // Activities
        const actList = document.getElementById('ai_modal_activities_list');
        actList.innerHTML = (recs.activities || []).map(a => `
            <div class="bg-gray-800 p-3 rounded-xl border border-gray-700 flex gap-3">
                <div class="w-8 h-8 rounded-lg bg-orange-500/20 text-orange-400 flex items-center justify-center font-bold text-xs shrink-0"><i class="fas fa-running"></i></div>
                <div><h5 class="text-sm font-bold text-white">${a.activity_name}</h5><p class="text-xs text-gray-400 mt-1 line-clamp-2">${a.reason}</p></div>
            </div>`).join('') || '<p class="text-gray-500 text-xs italic">No activities.</p>';

    } catch(e) {
        console.error(e);
        setAIText('ai_modal_response', "Failed to load details.");
    }
}

function renderAICharts(charts) {
    const usageDiv = document.querySelector("#aiUsageChart");
    if(usageDiv && charts.usage_line_chart) {
        usageDiv.innerHTML = "";
        const options = {
            series: [{ name: 'Requests', data: charts.usage_line_chart.map(d => d.total_requests) }],
            chart: { type: 'area', height: 250, toolbar: {show:false}, background: 'transparent', fontFamily: 'Plus Jakarta Sans, sans-serif' },
            stroke: { curve: 'smooth', width: 2 },
            fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.6, opacityTo: 0.1, stops: [0, 100] } },
            colors: ['#818cf8'],
            xaxis: { categories: charts.usage_line_chart.map(d => d.day), labels: { style: { colors: '#9ca3af' } }, axisBorder: {show:false}, axisTicks: {show:false} },
            yaxis: { labels: { style: { colors: '#9ca3af' }, formatter: (val) => val.toFixed(0) } },
            grid: { borderColor: '#374151', strokeDashArray: 4 },
            tooltip: { theme: 'dark' }
        };
        if(aiUsageChart) aiUsageChart.destroy();
        aiUsageChart = new ApexCharts(usageDiv, options);
        aiUsageChart.render();
    }

    const feedbackDiv = document.querySelector("#aiFeedbackChart");
    if(feedbackDiv && charts.feedback_pie_chart) {
        feedbackDiv.innerHTML = "";
        const fd = charts.feedback_pie_chart;
        const values = [fd.success, fd.neutral, fd.failure];
        if(values.every(v => v === 0)) {
            feedbackDiv.innerHTML = `<div class="h-full flex items-center justify-center text-gray-500 text-xs">No feedback data.</div>`;
            return;
        }
        const options = {
            series: values,
            labels: ['Positive', 'Neutral', 'Negative'],
            chart: { type: 'donut', height: 250, background: 'transparent', fontFamily: 'Plus Jakarta Sans, sans-serif' },
            colors: ['#10b981', '#6b7280', '#ef4444'],
            plotOptions: { pie: { donut: { size: '75%', labels: { show: true, total: { show: true, color: '#fff' } } } } },
            legend: { position: 'bottom', labels: { colors: '#d1d5db' } },
            stroke: { show: false },
            tooltip: { theme: 'dark' }
        };
        if(aiFeedbackChart) aiFeedbackChart.destroy();
        aiFeedbackChart = new ApexCharts(feedbackDiv, options);
        aiFeedbackChart.render();
    }
}

window.filterAISessions = function() {
    const search = document.getElementById('aiSessionSearch').value.toLowerCase();
    // Simple client-side filter
    const filtered = globalAISessions.filter(s => 
        (s.user_email || '').toLowerCase().includes(search) || 
        (s.session_id || '').toLowerCase().includes(search)
    );
    renderAISessionsTable(filtered);
}

// --- SESSION DETAIL MODAL ---
window.openAISessionDetail = async function(sessionId) {
    openModal('aiSessionModal');
    // Set Loading State
    document.getElementById('ai_modal_response').innerText = "Loading detailed analysis...";
    
    try {
        const res = await adminFetch(`/admin/ai/sessions/${sessionId}`);
        if(!res.ok) throw new Error("Failed to fetch details");
        const data = await res.json();
        
        const meta = data.session_metadata;
        const recs = data.recommendations;

        // 1. Header & Sidebar
        setText('ai_modal_session_id', `Session ID: ${meta.session_id}`);
        setText('ai_modal_username', `${meta.user_firstname} ${meta.user_lastname}`);
        setText('ai_modal_email', meta.user_email);
        document.getElementById('ai_modal_avatar').src = `https://ui-avatars.com/api/?name=${meta.user_firstname}+${meta.user_lastname}&background=random`;
        
        setText('ai_modal_model', meta.ai_model_used);
        setText('ai_modal_glucose', meta.latest_glucose_value || '-');
        setText('ai_modal_hba1c', meta.latest_hba1c ? meta.latest_hba1c + '%' : '-');

        // Confidence Bar
        const conf = meta.ai_confidence_score || 0;
        const confPct = (conf * 100).toFixed(1) + '%';
        document.getElementById('ai_modal_confidence_bar').style.width = confPct;
        setText('ai_modal_confidence_text', confPct);

        // 2. AI Response
        setText('ai_modal_response', meta.insights_response || meta.analysis_summary || "No textual analysis provided.");

        // 3. Recommendations - Foods
        const foodList = document.getElementById('ai_modal_foods_list');
        foodList.innerHTML = '';
        if(recs.foods && recs.foods.length > 0) {
            foodList.innerHTML = recs.foods.map(f => `
                <div class="bg-gray-800 p-3 rounded-xl border border-gray-700 flex gap-3">
                    <div class="w-10 h-10 rounded-lg bg-green-500/20 text-green-400 flex items-center justify-center font-bold text-xs shrink-0">
                        <i class="fas fa-apple-alt"></i>
                    </div>
                    <div>
                        <h5 class="text-sm font-bold text-white">${f.food_name}</h5>
                        <p class="text-xs text-gray-400 mt-1 line-clamp-2">${f.reason}</p>
                        <div class="mt-2 flex gap-2">
                            <span class="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded">${f.carbs_grams}g Carbs</span>
                            <span class="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded">GL: ${f.glycemic_load}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            foodList.innerHTML = `<p class="text-gray-500 text-xs italic">No food recommendations.</p>`;
        }

        // 4. Recommendations - Activities
        const actList = document.getElementById('ai_modal_activities_list');
        actList.innerHTML = '';
        if(recs.activities && recs.activities.length > 0) {
            actList.innerHTML = recs.activities.map(a => `
                <div class="bg-gray-800 p-3 rounded-xl border border-gray-700 flex gap-3">
                    <div class="w-10 h-10 rounded-lg bg-orange-500/20 text-orange-400 flex items-center justify-center font-bold text-xs shrink-0">
                        <i class="fas fa-running"></i>
                    </div>
                    <div>
                        <h5 class="text-sm font-bold text-white">${a.activity_name}</h5>
                        <p class="text-xs text-gray-400 mt-1 line-clamp-2">${a.reason}</p>
                        <div class="mt-2 flex gap-2">
                            <span class="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded">${a.recommended_duration_minutes} mins</span>
                            <span class="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded capitalize">${a.recommended_intensity}</span>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            actList.innerHTML = `<p class="text-gray-500 text-xs italic">No activity recommendations.</p>`;
        }

    } catch(e) {
        console.error("Session Detail Error:", e);
        alert("Failed to load session details.");
        closeModal('aiSessionModal');
    }
}

// =========================================================
//  SECTION: AUTH LOGS PAGE LOGIC (FIXED)
// =========================================================

let globalAuthLogs = [];

async function initAuthLogsPage() {
    console.log("Init Auth Logs Page");
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'Security Logs';

    await loadAuthLogs();
}

async function loadAuthLogs() {
    const tbody = document.getElementById('authLogsTableBody');
    // Set loading state
    if(tbody) tbody.innerHTML = `<tr><td colspan="5" class="p-10 text-center text-gray-500"><i class="fas fa-circle-notch fa-spin text-2xl mb-2"></i><br>Loading Logs...</td></tr>`;

    try {
        // Fetch Logs
        const res = await adminFetch('/admin/logs/auth'); 
        if(!res.ok) throw new Error("Failed to load logs");
        
        const data = await res.json();
        
        // Handle if API returns array directly OR object { logs: [...] }
        globalAuthLogs = Array.isArray(data) ? data : (data.logs || []);
        
        // 1. Calculate Stats
        updateAuthLogStats(globalAuthLogs);

        // 2. Render Table (Bypass debounce for initial load)
        _performAuthLogFilter(); 

    } catch(e) {
        console.error("Auth Log Error:", e);
        if(tbody) tbody.innerHTML = `<tr><td colspan="5" class="p-10 text-center text-red-400">Failed to load data. <br><span class="text-xs">${e.message}</span></td></tr>`;
    }
}

// --- HELPER: Determine Status from Log Data ---
function getLogStatus(log) {
    // 1. Trust 'log_level' first
    const level = (log.log_level || '').toLowerCase();
    if (level === 'error') return 'failed';
    
    // 2. Analyze text content
    const text = ((log.log_action || '') + ' ' + (log.log_message || '')).toLowerCase();
    
    if (text.includes('success') || text.includes('verified') || text.includes('authorized')) return 'success';
    if (text.includes('fail') || text.includes('error') || text.includes('denied') || text.includes('not found')) return 'failed';
    
    return 'info'; // Default
}

function updateAuthLogStats(logs) {
    const total = logs.length;
    let success = 0;
    let failed = 0;
    const uniqueUsers = new Set();

    logs.forEach(l => {
        const status = getLogStatus(l);
        if (status === 'success') success++;
        if (status === 'failed') failed++;
        if (l.user_id) uniqueUsers.add(l.user_id);
    });

    setText('al_stat_total', total);
    setText('al_stat_info', logs.length - success - failed); // Info/Neutral
    setText('al_stat_warn', failed); // Errors/Failures
    setText('al_stat_users', uniqueUsers.size);
}

// --- FILTERING LOGIC (Internal) ---
const _performAuthLogFilter = function() {
    const search = document.getElementById('authLogSearch').value.toLowerCase();
    const levelFilter = document.getElementById('authLogLevelFilter').value.toLowerCase();
    const startStr = document.getElementById('authLogStartDate').value;
    const endStr = document.getElementById('authLogEndDate').value;

    const filtered = globalAuthLogs.filter(log => {
        // 1. Search (ID, User ID, Message)
        const logId = (log.log_id || '').toLowerCase();
        const userId = (log.user_id || '').toLowerCase();
        const msg = (log.log_message || '').toLowerCase();
        const matchSearch = logId.includes(search) || userId.includes(search) || msg.includes(search);

        // 2. Level Filter
        const level = (log.log_level || 'info').toLowerCase();
        // Map UI filter values to API values if needed, or simple direct match
        const matchLevel = levelFilter === 'all' || level === levelFilter;

        // 3. Date Range Filter
        let matchDate = true;
        if (startStr || endStr) {
            const logDate = new Date(log.created_at);
            logDate.setHours(0,0,0,0); 

            if (startStr) {
                const startDate = new Date(startStr);
                if (logDate < startDate) matchDate = false;
            }
            if (endStr) {
                const endDate = new Date(endStr);
                if (logDate > endDate) matchDate = false;
            }
        }

        return matchSearch && matchLevel && matchDate;
    });

    renderAuthLogsTable(filtered);
};

// Expose Debounced Version for HTML Input
window.filterAuthLogs = debounce(_performAuthLogFilter, 300);

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
    };
}

// --- RENDERING ---
function renderAuthLogsTable(logs) {
    const tbody = document.getElementById('authLogsTableBody');
    const countEl = document.getElementById('authLogCount');
    
    if(countEl) countEl.innerText = `Showing ${logs.length} logs`;
    if(!tbody) return;

    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-10 text-center text-gray-500 border-dashed border-t border-gray-700">No logs found matching filters.</td></tr>`;
        return;
    }

    // PERFORMANCE FIX: Limit to first 100 rows to prevent freezing
    const subset = logs.slice(0, 100);

    tbody.innerHTML = subset.map(log => {
        // 1. Level Badge
        const level = (log.log_level || 'info').toLowerCase();
        let levelBadge = `<span class="bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide">Info</span>`;
        
        if (level === 'warning') {
            levelBadge = `<span class="bg-orange-500/10 text-orange-400 border border-orange-500/20 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide">Warning</span>`;
        } else if (level === 'error') {
            levelBadge = `<span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide">Error</span>`;
        }

        // 2. Action Icon
        const actionRaw = (log.log_action || 'unknown').replace(/_/g, ' ');
        const categoryRaw = (log.log_category || '').toUpperCase();
        let actionIcon = '<i class="fas fa-circle text-gray-500 text-xs"></i>';
        
        if(actionRaw.includes('login')) actionIcon = '<i class="fas fa-sign-in-alt text-blue-400"></i>';
        else if(actionRaw.includes('logout')) actionIcon = '<i class="fas fa-sign-out-alt text-gray-400"></i>';
        else if(actionRaw.includes('otp')) actionIcon = '<i class="fas fa-key text-yellow-400"></i>';

        // 3. Formatting
        const dateObj = new Date(log.created_at);
        const dateStr = dateObj.toLocaleDateString('id-ID', { day: 'numeric', month: 'short' });
        const timeStr = dateObj.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const logIdShort = log.log_id ? log.log_id.substring(0, 8) : '';

        return `
        <tr class="hover:bg-gray-800/50 transition border-b border-gray-700/50 last:border-0 group">
            <td class="p-4 whitespace-nowrap">
                <div class="flex flex-col">
                    <span class="text-sm font-bold text-gray-300">${timeStr}</span>
                    <span class="text-[10px] text-gray-500">${dateStr}</span>
                </div>
            </td>
            <td class="p-4 text-center">
                ${levelBadge}
            </td>
            <td class="p-4">
                <div class="flex items-center gap-2">
                    <span class="text-[9px] font-bold bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded border border-gray-700 tracking-wider">${categoryRaw}</span>
                    <span class="text-sm font-bold text-white capitalize">${actionRaw}</span>
                </div>
                <div class="text-[10px] text-gray-600 font-mono mt-1 select-all">ID: ${logIdShort}</div>
            </td>
            <td class="p-4">
                <p class="text-xs text-gray-400 leading-snug max-w-md">${log.log_message}</p>
                ${ log.user_agent ? `<div class="text-[9px] text-gray-600 mt-1 truncate max-w-xs" title="${log.user_agent}">${log.user_agent}</div>` : ''}
            </td>
            <td class="p-4 text-right">
                <div class="flex flex-col items-end">
                    <span class="text-xs font-mono text-indigo-400 select-all" title="${log.user_id}">${log.user_id ? log.user_id.substring(0, 8)+'...' : 'System'}</span>
                    <span class="text-[10px] text-gray-500 font-mono mt-0.5">${log.ip_address || 'IP Hidden'}</span>
                </div>
            </td>
        </tr>
        `;
    }).join('');
}

// =========================================================
//  SECTION: ADMIN ACCESS PAGE LOGIC
// =========================================================

let globalAdmins = [];

async function initAdminAccessPage() {
    console.log("Init Admin Access Page");
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'Admin Access';

    await loadAdminsList();
}

async function loadAdminsList() {
    const tbody = document.getElementById('adminsTableBody');
    if(tbody) tbody.innerHTML = `<tr><td colspan="5" class="p-10 text-center text-gray-500"><i class="fas fa-circle-notch fa-spin text-2xl mb-2"></i><br>Loading Admins...</td></tr>`;

    try {
        const res = await adminFetch('/admin/access/admins');
        if(!res.ok) throw new Error("Failed to load admins");
        
        globalAdmins = await res.json();
        
        // Stats
        const total = globalAdmins.length;
        const supers = globalAdmins.filter(a => a.role === 'super_admin').length;
        
        setText('adm_stat_total', total);
        setText('adm_stat_super', supers);
        setText('adm_stat_standard', total - supers);

        filterAdminsList();

    } catch(e) {
        console.error("Admin List Error:", e);
        if(tbody) tbody.innerHTML = `<tr><td colspan="5" class="p-10 text-center text-red-400">Failed to load data.</td></tr>`;
    }
}

// --- FILTERING ---
window.filterAdminsList = function() {
    const search = document.getElementById('adminSearch').value.toLowerCase();
    
    const filtered = globalAdmins.filter(a => 
        a.username.toLowerCase().includes(search) || 
        a.role.toLowerCase().includes(search)
    );

    renderAdminsTable(filtered);
}

// --- RENDERING ---
function renderAdminsTable(admins) {
    const tbody = document.getElementById('adminsTableBody');
    if(!tbody) return;

    if(admins.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-10 text-center text-gray-500 border-dashed border-t border-gray-700">No admins found.</td></tr>`;
        return;
    }

    tbody.innerHTML = admins.map(a => {
        // Role Badge
        let roleBadge = `<span class="bg-gray-700 text-gray-300 border border-gray-600 px-2 py-1 rounded text-[10px] font-bold uppercase">Admin</span>`;
        if(a.role === 'super_admin') {
            roleBadge = `<span class="bg-purple-500/10 text-purple-300 border border-purple-500/30 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide flex items-center justify-center w-fit mx-auto gap-1"><i class="fas fa-crown text-[9px]"></i> Super Admin</span>`;
        } else {
            roleBadge = `<span class="bg-blue-500/10 text-blue-300 border border-blue-500/30 px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wide flex items-center justify-center w-fit mx-auto">Standard</span>`;
        }

        // Dates
        const created = new Date(a.created_at).toLocaleDateString();
        const lastLogin = a.last_login_at ? new Date(a.last_login_at).toLocaleString() : '<span class="text-gray-600 italic">Never</span>';
        const avatar = `https://ui-avatars.com/api/?name=${a.username}&background=random&color=fff`;

        return `
        <tr class="hover:bg-gray-800/50 transition border-b border-gray-700/50 last:border-0 group">
            <td class="p-4">
                <div class="flex items-center gap-3">
                    <img src="${avatar}" class="w-8 h-8 rounded-full border border-gray-600 bg-gray-700">
                    <div>
                        <div class="font-bold text-white text-sm">${a.username}</div>
                        <div class="text-[10px] text-gray-500 font-mono">ID: ${a.admin_id.substring(0,8)}...</div>
                    </div>
                </div>
            </td>
            <td class="p-4 text-center">
                ${roleBadge}
            </td>
            <td class="p-4 text-center text-xs text-gray-400 font-mono">
                ${lastLogin}
            </td>
            <td class="p-4 text-center text-xs text-gray-500">
                ${created}
            </td>
            <td class="p-4 text-right">
                <div class="flex items-center justify-end gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition">
                    <button onclick="openEditRoleModal('${a.admin_id}', '${a.username}', '${a.role}')" class="p-2 bg-gray-700 hover:bg-blue-600 text-white rounded-lg transition shadow-sm" title="Edit Role">
                        <i class="fas fa-user-tag"></i>
                    </button>
                    <button onclick="deleteAdmin('${a.admin_id}')" class="p-2 bg-gray-700 hover:bg-red-600 text-white rounded-lg transition shadow-sm" title="Delete Account">
                        <i class="fas fa-trash-alt"></i>
                    </button>
                </div>
            </td>
        </tr>
        `;
    }).join('');
}

// --- CREATE ADMIN ---
window.openCreateAdminModal = function() {
    document.getElementById('newAdminUsername').value = '';
    document.getElementById('newAdminPassword').value = '';
    document.getElementById('newAdminRole').value = 'admin';
    openModal('createAdminModal');
}

window.submitCreateAdmin = async function() {
    const username = document.getElementById('newAdminUsername').value;
    const password = document.getElementById('newAdminPassword').value;
    const role = document.getElementById('newAdminRole').value;
    const btn = document.getElementById('btnCreateAdmin');

    if(!username || !password) return alert("Please fill all fields.");

    setLoading(btn, true);

    try {
        const res = await adminFetch('/admin/access/admin', {
            method: 'POST',
            body: JSON.stringify({ username, password, role })
        });

        if(res.ok) {
            alert("Admin created successfully!");
            closeModal('createAdminModal');
            loadAdminsList();
        } else {
            const err = await res.json();
            alert("Error: " + (err.error || "Failed to create admin"));
        }
    } catch(e) {
        alert("Connection error");
    } finally {
        setLoading(btn, false, "Create Account");
    }
}

// --- EDIT ROLE ---
window.openEditRoleModal = function(id, username, role) {
    document.getElementById('editRoleAdminId').value = id;
    document.getElementById('editRoleUsername').innerText = username;
    document.getElementById('editRoleSelect').value = role;
    openModal('editRoleModal');
}

window.submitUpdateRole = async function() {
    const id = document.getElementById('editRoleAdminId').value;
    const role = document.getElementById('editRoleSelect').value;
    const btn = document.getElementById('btnUpdateRole');

    setLoading(btn, true);

    try {
        const res = await adminFetch(`/admin/access/admin/role/${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ role })
        });

        if(res.ok) {
            alert("Role updated successfully!");
            closeModal('editRoleModal');
            loadAdminsList();
        } else {
            alert("Failed to update role");
        }
    } catch(e) {
        alert("Connection error");
    } finally {
        setLoading(btn, false, "Save");
    }
}

// --- DELETE ADMIN ---
window.deleteAdmin = async function(id) {
    if(!confirm("Are you sure you want to delete this admin account? This cannot be undone.")) return;

    try {
        const res = await adminFetch(`/admin/access/admin/${id}`, { method: 'DELETE' });
        if(res.ok) {
            alert("Admin deleted.");
            loadAdminsList();
        } else {
            alert("Failed to delete admin.");
        }
    } catch(e) {
        alert("Connection error");
    }
}

// =========================================================
//  SECTION: SERVER HEALTH LOGIC (DAILY CHART)
// =========================================================

let chartCPU, chartRAM, chartDisk;

// Data Arrays
// Format: { x: timestamp, y: value }
let dataCPU = loadDailyData('health_cpu');
let dataRAM = loadDailyData('health_ram');
let dataDisk = loadDailyData('health_disk');

let uptimeInterval = null;
let serverStartTime = null;

async function initServerHealthPage() {
    console.log("Init Server Health (Daily View)");
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'System Health';

    // Cleanup old instances
    if(chartCPU) { chartCPU.destroy(); chartCPU = null; }
    if(chartRAM) { chartRAM.destroy(); chartRAM = null; }
    if(chartDisk) { chartDisk.destroy(); chartDisk = null; }
    if(uptimeInterval) clearInterval(uptimeInterval);

    initHealthCharts();
    await fetchServerHealthSnapshot();
}

// Helper to load data ONLY if it matches today's date
function loadDailyData(key) {
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    
    try {
        const parsed = JSON.parse(raw);
        if (parsed.length > 0) {
            const lastPoint = new Date(parsed[parsed.length - 1].x);
            const today = new Date();
            // If data is not from today, discard it
            if (lastPoint.getDate() !== today.getDate() || 
                lastPoint.getMonth() !== today.getMonth()) {
                return [];
            }
        }
        return parsed;
    } catch (e) { return []; }
}

function initHealthCharts() {
    // Calculate Today's 00:00 and 23:59 in WIB
    // We create a date, force it to Jakarta time, then get the timestamp
    const now = new Date();
    
    // Create start/end for the current date in local time (simplest for daily view)
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0);
    const endOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59);

    const commonOptions = {
        chart: {
            type: 'area',
            height: 280,
            animations: { enabled: false }, // Disable for performance
            toolbar: { show: true, tools: { download: false, selection: true, zoom: true, pan: true } },
            background: 'transparent'
        },
        stroke: { curve: 'straight', width: 2 },
        fill: { 
            type: 'gradient', 
            gradient: { shadeIntensity: 1, opacityFrom: 0.4, opacityTo: 0.05, stops: [0, 100] } 
        },
        dataLabels: { enabled: false },
        xaxis: {
            type: 'datetime',
            min: startOfDay.getTime(),
            max: endOfDay.getTime(),
            labels: { 
                show: true,
                style: { colors: '#9ca3af', fontSize: '11px' },
                // --- FIX 1: Force WIB Timezone for X-Axis Labels ---
                formatter: function(val, timestamp) {
                    return new Date(timestamp).toLocaleTimeString('id-ID', { 
                        timeZone: 'Asia/Jakarta', 
                        hour: '2-digit', 
                        minute: '2-digit',
                        hour12: false 
                    });
                }
            },
            tooltip: { enabled: false }
        },
        yaxis: {
            min: 0, 
            max: 100,
            labels: { 
                style: { colors: '#9ca3af' },
                formatter: (val) => val.toFixed(0)
            },
            grid: { borderColor: '#374151', strokeDashArray: 4 }
        },
        grid: {
            show: true,
            borderColor: '#374151',
            strokeDashArray: 4
        },
        tooltip: {
            theme: 'dark',
            // --- FIX 2: Force WIB Timezone for Tooltip Title ---
            x: { 
                formatter: function(val) {
                    return new Date(val).toLocaleString('id-ID', { 
                        timeZone: 'Asia/Jakarta',
                        day: 'numeric',
                        month: 'short',
                        hour: '2-digit', 
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false
                    }) + " WIB";
                } 
            },
            y: { formatter: (val) => val.toFixed(1) + "%" }
        }
    };

    // 1. CPU Chart
    if(document.querySelector("#chart_cpu")) {
        const optCPU = { ...commonOptions, series: [{ name: 'CPU', data: dataCPU }], colors: ['#6366f1'] };
        chartCPU = new ApexCharts(document.querySelector("#chart_cpu"), optCPU);
        chartCPU.render();
    }

    // 2. RAM Chart
    if(document.querySelector("#chart_ram")) {
        const optRAM = { ...commonOptions, series: [{ name: 'Memory', data: dataRAM }], colors: ['#a855f7'] };
        chartRAM = new ApexCharts(document.querySelector("#chart_ram"), optRAM);
        chartRAM.render();
    }

    // 3. Disk Chart
    if(document.querySelector("#chart_disk")) {
        const optDisk = { ...commonOptions, series: [{ name: 'Disk', data: dataDisk }], colors: ['#f97316'] };
        chartDisk = new ApexCharts(document.querySelector("#chart_disk"), optDisk);
        chartDisk.render();
    }
}

async function fetchServerHealthSnapshot() {
    try {
        const res = await adminFetch('/admin/server/health'); 
        if(!res.ok) throw new Error("Failed");
        
        const data = await res.json();

        // Populate Static Info
        if (data.runtime) {
            setText('sys_hostname', data.runtime.hostname || '-');
            setText('sys_os', `${data.runtime.os || ''} ${data.runtime.platform || ''}`);
            setText('sys_arch', data.runtime.arch || '-');
            
            if (data.runtime.start_time) {
                startUptimeCounter(data.runtime.start_time);
            }
        }

        if (data.cpu) setText('cpu_cores', `${data.cpu.cores} Cores`);
        if (data.memory) {
            setText('ram_total', (data.memory.total_gb || '0 GB'));
            setText('ram_used_gb', (data.memory.used_gb || '0 GB') + ' used');
        }
        if (data.disk) {
            setText('disk_total', (data.disk.total_gb || '0 GB'));
            setText('disk_used_gb', (data.disk.used_gb || '0 GB') + ' used');
        }

        // Push Initial Data
        updateHealthUI({
            cpu_usage: data.cpu?.usage_percent || '0%',
            ram_usage: data.memory?.used_percent || '0%',
            disk_usage: data.disk?.used_percent || '0%'
        });

    } catch(e) { console.error("Snapshot Error", e); }
}

function startUptimeCounter(startTimeStr) {
    if(uptimeInterval) clearInterval(uptimeInterval);
    serverStartTime = new Date(startTimeStr);
    
    // Update immediately
    updateUptimeDisplay();
    // Update every second
    uptimeInterval = setInterval(updateUptimeDisplay, 1000);
}

function updateUptimeDisplay() {
    const uptimeEl = document.getElementById('sys_uptime');
    if(!uptimeEl || !serverStartTime) return;
    
    const now = new Date();
    const diffMs = now - serverStartTime;
    
    const diffSecs = Math.floor(diffMs / 1000);
    const days = Math.floor(diffSecs / (3600 * 24));
    const hours = Math.floor((diffSecs % (3600 * 24)) / 3600);
    const minutes = Math.floor((diffSecs % 3600) / 60);
    const seconds = diffSecs % 60;

    let str = "";
    if(days > 0) str += `${days}d `;
    if(hours > 0) str += `${hours}h `;
    str += `${minutes}m ${seconds}s`;

    uptimeEl.innerText = str;
}

// WebSocket / Update Handler
function updateHealthUI(data) {
    const cpuVal = document.getElementById('rt_cpu_val');
    if (!cpuVal) return; 

    cpuVal.innerText = data.cpu_usage;
    setText('rt_ram_val', data.ram_usage);
    setText('rt_disk_val', data.disk_usage);

    // Parse Numbers
    const cpuNum = parseFloat(data.cpu_usage.replace('%', ''));
    const ramNum = parseFloat(data.ram_usage.replace('%', ''));
    const diskNum = parseFloat(data.disk_usage.replace('%', ''));

    // Update Arrays
    const now = new Date().getTime();
    
    // Push new data point
    const updateArray = (arr, val, key) => {
        arr.push({ x: now, y: val });
        // Optional: Limit points if it gets too heavy (e.g., 5000 points = ~2.7 hours at 2s interval)
        // If you want full 24h, you might need to increase this or downsample.
        if (arr.length > 5000) arr.shift(); 
        localStorage.setItem(key, JSON.stringify(arr));
    };

    updateArray(dataCPU, cpuNum, 'health_cpu');
    updateArray(dataRAM, ramNum, 'health_ram');
    updateArray(dataDisk, diskNum, 'health_disk');

    // Update Charts
    // Note: We use updateSeries with just the data array for better performance
    if(chartCPU) chartCPU.updateSeries([{ data: dataCPU }]);
    if(chartRAM) chartRAM.updateSeries([{ data: dataRAM }]);
    if(chartDisk) chartDisk.updateSeries([{ data: dataDisk }]);
}

// =========================================================
//  SECTION: ADMIN SETTINGS PAGE LOGIC
// =========================================================

async function initSettingsPage() {
    console.log("Init Settings Page");
    const titleEl = document.getElementById('page-title');
    if(titleEl) titleEl.innerText = 'Settings';

    // 1. Load Profile Data from LocalStorage (Source of Truth for display)
    const storedUser = localStorage.getItem('admin_username') || 'Admin';
    const storedRole = localStorage.getItem('admin_role') || 'ADMIN';
    
    setText('settingsName', storedUser);
    setText('settingsRole', storedRole.toUpperCase());
    
    // Set input value
    const inputUser = document.getElementById('set_username');
    if(inputUser) inputUser.value = storedUser;
    
    // Avatar
    const avatar = document.getElementById('settingsAvatar');
    if(avatar) avatar.src = `https://ui-avatars.com/api/?name=${storedUser}&background=random&color=fff`;

    // 2. Dummy System Config Load (Just Visual)
    console.log("Dummy System Config Loaded");
}

// --- PROFILE UPDATE (Username) ---
window.updateAdminProfile = async function() {
    const btn = document.getElementById('btnSaveProfile');
    const newUsername = document.getElementById('set_username').value;

    if(!newUsername) return alert("Username cannot be empty");

    setLoading(btn, true);

    try {
        // MATCHING GO HANDLER: PATCH /admin/update/username
        const res = await adminFetch('/admin/update/username', {
            method: 'PATCH', // Changed to PATCH
            body: JSON.stringify({ username: newUsername })
        });

        if(res.ok) {
            // Update LocalStorage and UI
            localStorage.setItem('admin_username', newUsername);
            setText('settingsName', newUsername);
            document.getElementById('settingsAvatar').src = `https://ui-avatars.com/api/?name=${newUsername}&background=random&color=fff`;
            
            // Update the Sidebar name immediately if possible
            const sidebarName = document.querySelector('.sidebar-username');
            if(sidebarName) sidebarName.innerText = newUsername;

            alert("Username updated successfully!");
        } else {
            const err = await res.json();
            alert("Error: " + (err.error || "Update failed"));
        }
    } catch(e) {
        console.error(e);
        alert("Connection error");
    } finally {
        setLoading(btn, false, "Update Username");
    }
}

// --- PASSWORD UPDATE ---
window.updateAdminPassword = async function() {
    const btn = document.getElementById('btnSavePass');
    const currentPass = document.getElementById('set_curr_pass').value;
    const newPass = document.getElementById('set_new_pass').value;
    const confirmPass = document.getElementById('set_confirm_pass').value;

    if(!currentPass || !newPass || !confirmPass) return alert("Please fill all password fields");
    if(newPass !== confirmPass) return alert("New passwords do not match");

    setLoading(btn, true);

    try {
        // MATCHING GO HANDLER: PATCH /admin/update/password
        const res = await adminFetch('/admin/update/password', {
            method: 'PATCH', // Changed to PATCH
            body: JSON.stringify({ 
                current_password: currentPass,
                new_password: newPass
            })
        });

        if(res.ok) {
            alert("Password changed successfully.");
            // Clear fields
            document.getElementById('set_curr_pass').value = '';
            document.getElementById('set_new_pass').value = '';
            document.getElementById('set_confirm_pass').value = '';
        } else {
            const txt = await res.text(); 
            let errMsg = "Failed to change password";
            try {
                const jsonErr = JSON.parse(txt);
                errMsg = jsonErr.error || jsonErr.message || errMsg;
            } catch(e) {
                errMsg = txt; 
            }
            alert("Error: " + errMsg);
        }
    } catch(e) {
        console.error(e);
        alert("Connection error");
    } finally {
        setLoading(btn, false, "Change Password");
    }
}

// --- DUMMY FEATURES ---

window.toggleDummyFeature = function(featureName) {
    // Just a visual toggle with alert
    setTimeout(() => {
        alert(`[DUMMY FEATURE] \n${featureName} setting toggled visually.\nNo backend logic implemented yet.`);
    }, 100);
}

window.clearSystemCache = function() {
    if(!confirm("Are you sure you want to clear the system cache?")) return;
    
    setTimeout(() => {
        alert(`[DUMMY FEATURE] \nSystem cache clear request sent.\n(This is a simulation)`);
    }, 500);
}