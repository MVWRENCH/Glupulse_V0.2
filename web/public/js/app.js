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
    
    // Fallback
    '/': '/static/views/dashboard.html'
};

const router = async () => {
    // 1. Determine Path
    let path = window.location.pathname;
    
    // Handle root or index.html direct access
    if (path === '/' || path === '/index.html') path = '/seller/dashboard';
    
    // 2. Get Route (Default to Dashboard if path not found in map)
    const route = routes[path] || routes['/seller/dashboard'];

    // 3. Update Sidebar Active State
    document.querySelectorAll('.sidebar-item').forEach(el => {
        el.classList.remove('active', 'text-brand-600', 'bg-brand-50', 'border-r-4', 'border-brand-600');
        el.classList.add('text-gray-500', 'hover:text-brand-600', 'hover:bg-brand-50');
        
        // Match link href to current path
        if(el.getAttribute('href') === path) {
            el.classList.remove('text-gray-500', 'hover:text-brand-600', 'hover:bg-brand-50');
            el.classList.add('active', 'text-brand-600', 'bg-brand-50', 'border-r-4', 'border-brand-600');
        }
    });

    // 4. Update Header Action Button (Only show "Add" on Menu page)
    const actionBtn = document.getElementById('header-action-btn');
    if (actionBtn) {
        if (path === '/seller/menu') actionBtn.classList.remove('hidden');
        else actionBtn.classList.add('hidden');
    }

    // 5. Fetch and Inject HTML
    try {
        const response = await fetch(route);
        if(!response.ok) throw new Error("View not found: " + route);
        const html = await response.text();
        document.getElementById('app').innerHTML = html;

        // 6. INITIALIZE PAGE SPECIFIC LOGIC
        // Clear previous dashboard interval if moving away from dashboard
        if (dashboardInterval) clearInterval(dashboardInterval);

       if (path === '/seller/menu') {
            initMenuPage();
        } 
        else if (path === '/seller/dashboard' || path === '/') {
            initDashboardPage();
        } 
        else if (path === '/seller/orders') {
            initOrdersPage();
        }
        else if (path == '/seller/reports') {
            initReportsPage();
        }
        else if (path === '/seller/store-profile') {
            initProfilePage();
        }
        else if (path == '/seller/store-reviews') {
            initReviewsPage();
        }

    } catch (error) {
        console.error(error);
        document.getElementById('app').innerHTML = `<div class="text-center py-20 text-gray-400"><h1>404 - Page content not found</h1><p>Trying to load: ${route}</p></div>`;
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

async function initMenuPage() {
    console.log("Menu Initialized");
    await loadCategories();
    fetchProducts();
}

async function loadCategories() {
    try {
        globalCategories = [{code: 'MAIN', name: 'Makanan Berat'}, {code: 'DRINK', name: 'Minuman'}, {code: 'SNACK', name: 'Cemilan'}];
        try {
            const res = await fetch(`${API_BASE_URL}/food/categories`);
            if(res.ok) globalCategories = await res.json();
        } catch(e) {}

        const filterSelect = document.getElementById('menuPageFilter');
        const modalSelect = document.getElementById('category');
        
        if(filterSelect && modalSelect) {
            filterSelect.innerHTML = '<option value="">Semua Kategori</option>';
            modalSelect.innerHTML = '<option value="" disabled selected>Pilih...</option>';
            globalCategories.forEach(cat => {
                const name = cat.name || cat.display_name;
                const code = cat.code || cat.category_code;
                filterSelect.add(new Option(name, code));
                modalSelect.add(new Option(name, code));
            });
        }
    } catch(e) { console.error("Cat Error", e); }
}

async function fetchProducts() {
    const grid = document.getElementById('productGrid');
    if(!grid) return;
    
    grid.innerHTML = `<div class="col-span-full text-center text-gray-400 py-10"><i class="fas fa-circle-notch fa-spin"></i> Memuat...</div>`;

    try {
        const res = await fetch(`${API_BASE_URL}/seller/menus?limit=100`);
        const data = await res.json();
        globalProducts = data || [];
        renderGrid(globalProducts);
    } catch (error) {
        grid.innerHTML = `<div class="col-span-full text-center text-red-500 py-10">Gagal mengambil data.</div>`;
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
        const statusBadge = (item.is_available !== false) 
            ? `<span class="bg-green-100 text-green-700 px-2 py-1 text-[10px] rounded font-bold uppercase">Ready</span>`
            : `<span class="bg-red-100 text-red-700 px-2 py-1 text-[10px] rounded font-bold uppercase">Habis</span>`;

        const card = document.createElement('div');
        card.className = 'bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden hover:shadow-lg transition group';
        card.innerHTML = `
            <div class="h-44 relative overflow-hidden bg-gray-100">
                <img src="${img}" class="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110">
                <div class="absolute top-3 right-3">${statusBadge}</div>
                <div class="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition flex items-center justify-center gap-3">
                    <button onclick="editProduct('${item.food_id}')" class="w-10 h-10 rounded-full bg-white text-brand-600 shadow"><i class="fas fa-pencil-alt"></i></button>
                    <button onclick="deleteProduct('${item.food_id}')" class="w-10 h-10 rounded-full bg-white text-red-500 shadow"><i class="fas fa-trash"></i></button>
                </div>
            </div>
            <div class="p-4">
                <h4 class="font-bold text-gray-800 truncate">${item.food_name}</h4>
                <p class="text-brand-600 font-extrabold text-sm mt-1">${price}</p>
            </div>
        `;
        grid.appendChild(card);
    });
}

// Global Search & Filter
window.handleGlobalSearch = function(val) {
    if(window.location.pathname === '/seller/menu') {
        const term = val.toLowerCase();
        const filtered = globalProducts.filter(p => p.food_name.toLowerCase().includes(term));
        renderGrid(filtered);
    }
};

window.filterMenuByCategory = function(code) {
    if (!code) { renderGrid(globalProducts); return; }
    const filtered = globalProducts.filter(p => {
        let cats = p.food_category || [];
        if (typeof cats === 'string') cats = cats.replace(/[{}"\\]/g, '').split(',');
        return Array.isArray(cats) && cats.includes(code);
    });
    renderGrid(filtered);
};


// --- MENU MODAL LOGIC ---

window.openProductModal = function() {
    const modal = document.getElementById('productModal');
    const backdrop = document.getElementById('modalBackdrop'); // Optional if using your new HTML structure
    if(!modal) return;

    // Reset Form & UI
    document.getElementById('productForm').reset();
    document.getElementById('foodId').value = '';
    
    // Reset Image
    const preview = document.getElementById('previewImage');
    const placeholder = document.getElementById('uploadPlaceholder');
    if(preview && placeholder) {
        preview.src = '';
        preview.classList.add('hidden');
        placeholder.classList.remove('hidden');
    }
    
    document.getElementById('modalTitle').innerText = "Tambah Menu Baru";
    
    // Try to switch tab if element exists (for old HTML compatibility)
    if(typeof switchModalTab === 'function' && document.getElementById('tab-general')) {
        switchModalTab('general');
    }

    modal.classList.remove('hidden');
};

window.closeProductModal = function() {
    const modal = document.getElementById('productModal');
    if(!modal) return;
    modal.classList.add('hidden');
};

// Keep this for old HTML compatibility, but check if elements exist
window.switchModalTab = function(tabName) {
    const btn = document.getElementById(`tab-${tabName}`);
    const view = document.getElementById(`modal-view-${tabName}`);
    if(btn && view) {
        document.querySelectorAll('.modal-tab-btn').forEach(el => el.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.modal-tab-content').forEach(el => el.classList.remove('active'));
        view.classList.add('active');
    }
};

window.handleImageUpload = function(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('previewImage').src = e.target.result;
            document.getElementById('previewImage').classList.remove('hidden');
            document.getElementById('uploadPlaceholder').classList.add('hidden');
            // Mock upload
            document.getElementById('photoUrl').value = "https://source.unsplash.com/random/400x400/?food," + Math.random(); 
        }
        reader.readAsDataURL(input.files[0]);
    }
};

window.saveProduct = async function() {
    const btn = document.getElementById('saveBtn') || document.querySelector('button[onclick="saveProduct()"]');
    const id = document.getElementById('foodId').value;
    const method = id ? 'PUT' : 'POST';
    const endpoint = id ? `${API_BASE_URL}/seller/menu/${id}` : `${API_BASE_URL}/seller/menu`;

    const name = document.getElementById('foodName').value;
    const price = parseFloat(document.getElementById('price').value);

    if(!name || isNaN(price)) { alert("Nama dan Harga wajib diisi"); return; }

    if(btn) {
        btn.disabled = true;
        btn.innerHTML = 'Menyimpan...';
    }

    const payload = {
        food_name: name,
        description: document.getElementById('description').value,
        price: price,
        currency: "IDR",
        photo_url: document.getElementById('photoUrl') ? document.getElementById('photoUrl').value : "",
        thumbnail_url: document.getElementById('photoUrl') ? document.getElementById('photoUrl').value : "",
        is_available: document.getElementById('isAvailable').checked,
        stock_count: parseInt(document.getElementById('stockCount').value) || -1,
        // Basic Array wrapping for simplicity
        food_category: [document.getElementById('category').value],
        
        // Nutrition defaults
        serving_size: document.getElementById('servingSize') ? document.getElementById('servingSize').value : "",
        calories: parseInt(document.getElementById('calories').value) || 0,
        // ... add other fields if they exist in your form
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
        } else {
            alert("Gagal menyimpan data");
        }
    } catch(e) { alert("Error koneksi"); }
    finally { 
        if(btn) {
            btn.disabled = false; 
            btn.innerHTML = '<i class="fas fa-save"></i> Simpan Menu'; 
        }
    }
};

window.editProduct = async function(id) {
    try {
        const res = await fetch(`${API_BASE_URL}/seller/menu/${id}`);
        const item = await res.json();
        
        openProductModal();
        document.getElementById('modalTitle').innerText = "Edit Menu";
        document.getElementById('foodId').value = item.food_id;
        document.getElementById('foodName').value = item.food_name;
        document.getElementById('price').value = item.price;
        if(document.getElementById('description')) document.getElementById('description').value = item.description || '';
        document.getElementById('isAvailable').checked = item.is_available !== false;
        
        // Handle other fields mapping as needed...
        
    } catch(e) { console.error(e); }
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
//  SECTION: PROFILE PAGE LOGIC (UPDATED)
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
//  PART B: USER ACCOUNT (Personal Info & Security)
// ---------------------------------------------------------

// 1. Fetch User Data
async function loadUserAccountData() {
    try {
        // Matches protected.GET("/profile")
        const res = await fetch(`${API_BASE_URL}/profile`); 
        if(!res.ok) throw new Error("Failed to load user profile");
        
        const data = await res.json();
        const profile = data.profile; // Matches UserProfileResponse

        // Populate Fields
        if(document.getElementById('display_user_id')) {
            document.getElementById('display_user_id').innerText = profile.user_id.substring(0, 8);
        }
        document.getElementById('account_username').value = profile.username;
        document.getElementById('account_email').value = profile.email;
        document.getElementById('account_first_name').value = profile.first_name;
        document.getElementById('account_last_name').value = profile.last_name;

        // Email Verification Badge
        const badge = document.getElementById('email_verified_badge');
        if(badge) {
            if(profile.is_email_verified) badge.classList.remove('hidden');
            else badge.classList.add('hidden');
        }

    } catch (e) {
        console.error("User Profile Error:", e);
    }
}

// 2. Update Personal Profile (First/Last Name)
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
            loadUserAccountData(); // Refresh to ensure sync
        } else {
            const data = await res.json();
            alert(data.error || "Gagal update profil.");
        }
    } catch(e) {
        alert("Error koneksi.");
    }
}

// 3. Update Username
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

// 4. Request Email Change
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

// 5. Change Password
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