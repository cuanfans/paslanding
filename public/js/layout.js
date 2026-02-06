// 1. Proteksi Client-Side: Cek token sebelum render apapun
if (!localStorage.getItem('admin_pass')) {
    window.location.href = '/login';
}

// 2. Inisialisasi Store Global AlpineJS
document.addEventListener('alpine:init', () => {
    Alpine.store('layout', {
        darkMode: localStorage.getItem('theme') === 'dark',
        sidebarOpen: window.innerWidth > 768,
        title: document.title || 'Admin Dashboard',
        
        toggleTheme() {
            this.darkMode = !this.darkMode;
            localStorage.setItem('theme', this.darkMode ? 'dark' : 'light');
            this.updateClass();
        },
        
        updateClass() {
            if (this.darkMode) document.documentElement.classList.add('dark');
            else document.documentElement.classList.remove('dark');
        },
        
        logout() {
            if (confirm('Yakin ingin keluar dari dashboard?')) {
                localStorage.removeItem('admin_pass');
                // Panggil logout API untuk hapus cookie di server
                fetch('/api/logout').finally(() => {
                    window.location.href = '/login';
                });
            }
        }
    });
    
    // Terapkan tema saat load
    Alpine.store('layout').updateClass();
});

// 3. Web Component untuk <admin-layout>
class AdminLayout extends HTMLElement {
    connectedCallback() {
        // Pindahkan konten asli (HTML di dalam <admin-layout>) ke fragment sementara
        const originalContent = document.createDocumentFragment();
        while (this.firstChild) {
            originalContent.appendChild(this.firstChild);
        }

        // Render struktur Dashboard
        this.innerHTML = `
            <div x-data class="flex h-screen bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-100 font-sans overflow-hidden">
                <aside :class="$store.layout.sidebarOpen ? 'w-64 translate-x-0' : 'w-64 -translate-x-full md:w-20 md:translate-x-0'" 
                       class="fixed md:relative z-30 h-full flex flex-col bg-white dark:bg-gray-800 border-r dark:border-gray-700 transition-all duration-300 shadow-xl md:shadow-none">
                    
                    <div class="h-16 flex items-center justify-center border-b dark:border-gray-700 shrink-0">
                        <span x-show="$store.layout.sidebarOpen" class="text-xl font-black text-blue-600 tracking-tighter">BlinkSite</span>
                        <span x-show="!$store.layout.sidebarOpen" class="text-xl font-bold text-blue-600 hidden md:block">B</span>
                    </div>

                    <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
                        ${this.link('/admin/dashboard', 'ph-squares-four', 'Dashboard')}
                        ${this.link('/admin/pages', 'ph-files', 'Halaman')}
                        ${this.link('/admin/reports', 'ph-chart-line-up', 'Laporan')}
                        ${this.link('/admin/analytics', 'ph-trend-up', 'Traffic')}
                        ${this.link('/admin/settings', 'ph-gear', 'Settings')}
                    </nav>

                    <div class="p-4 border-t dark:border-gray-700 shrink-0">
                        <button @click="$store.layout.logout()" class="flex items-center gap-3 text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 w-full p-2 rounded-lg transition-colors">
                            <i class="ph ph-sign-out text-xl"></i>
                            <span x-show="$store.layout.sidebarOpen" class="font-medium">Keluar</span>
                        </button>
                    </div>
                </aside>

                <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
                    <header class="h-16 bg-white dark:bg-gray-800 border-b dark:border-gray-700 flex justify-between items-center px-4 shadow-sm z-20 shrink-0">
                        <div class="flex items-center gap-4">
                            <button @click="$store.layout.sidebarOpen = !$store.layout.sidebarOpen" class="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors">
                                <i class="ph ph-list text-2xl"></i>
                            </button>
                            <h1 class="font-bold text-lg truncate" x-text="$store.layout.title"></h1>
                        </div>
                        <button @click="$store.layout.toggleTheme()" class="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-700 border dark:border-gray-600 transition-colors">
                            <i x-show="!$store.layout.darkMode" class="ph ph-moon text-xl"></i>
                            <i x-show="$store.layout.darkMode" class="ph ph-sun text-xl text-yellow-400"></i>
                        </button>
                    </header>

                    <main id="main-slot" class="flex-1 overflow-y-auto p-4 md:p-8 relative"></main>
                </div>
                
                <div x-show="$store.layout.sidebarOpen" 
                     @click="$store.layout.sidebarOpen = false" 
                     class="fixed inset-0 bg-black/50 z-20 md:hidden" 
                     x-transition.opacity></div>
            </div>
        `;

        // Masukkan kembali konten asli ke slot main
        this.querySelector('#main-slot').appendChild(originalContent);

        // Re-inisialisasi AlpineJS agar x-data di dalam konten terbaca
        setTimeout(() => {
            if (window.Alpine) {
                window.Alpine.discover(); // Cari directive baru
                window.Alpine.initTree(this); // Inisialisasi tree layout ini
            }
        }, 100);
    }

    link(href, icon, label) {
        const active = window.location.pathname.startsWith(href);
        const cls = active 
            ? 'bg-blue-600 text-white shadow-md' 
            : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700';
        
        return `
            <a href="${href}" class="${cls} flex items-center gap-3 px-3 py-3 rounded-lg transition-colors group">
                <i class="ph ${icon} text-xl shrink-0"></i>
                <span x-show="$store.layout.sidebarOpen" class="font-medium whitespace-nowrap">${label}</span>
            </a>
        `;
    }
}

customElements.define('admin-layout', AdminLayout);
