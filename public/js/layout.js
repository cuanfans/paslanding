// Cek Auth Global
if (!localStorage.getItem('admin_pass')) window.location.href = '/login';

class AdminLayout extends HTMLElement {
    connectedCallback() {
        // Ambil konten asli di dalam tag <admin-layout>
        const content = this.innerHTML;
        
        // Render Layout Full (Sidebar + Main Content)
        this.innerHTML = `
            <div x-data="{ sidebarOpen: false, darkMode: localStorage.getItem('theme') === 'dark' }" 
                 :class="{ 'dark': darkMode }" 
                 class="min-h-screen font-sans bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-100">
                
                <div class="md:hidden fixed top-0 left-0 right-0 h-16 bg-white dark:bg-gray-800 border-b dark:border-gray-700 flex items-center justify-between px-4 z-40">
                    <div class="font-black text-xl text-blue-600">BlinkSite</div>
                    <button @click="sidebarOpen = !sidebarOpen" class="text-gray-500 dark:text-gray-400">
                        <i class="ph ph-list text-2xl"></i>
                    </button>
                </div>

                <aside :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full'" 
                       class="fixed inset-y-0 left-0 w-64 bg-white dark:bg-gray-800 border-r dark:border-gray-700 z-50 md:translate-x-0 transition-transform duration-300 flex flex-col pt-16 md:pt-0 shadow-xl md:shadow-none">
                    
                    <div class="h-16 flex items-center px-6 border-b border-gray-100 dark:border-gray-700 hidden md:flex">
                        <h1 class="font-black text-2xl text-blue-600 tracking-tighter">Blink<span class="text-gray-800 dark:text-white">Site</span></h1>
                    </div>

                    <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
                        ${this.navLink('/admin/dashboard', 'ph-squares-four', 'Dashboard')}
                        ${this.navLink('/admin/pages', 'ph-files', 'Landing Pages')}
                        ${this.navLink('/admin/reports', 'ph-chart-line-up', 'Reports')}
                        ${this.navLink('/admin/settings', 'ph-gear', 'Settings')}
                    </nav>

                    <div class="p-4 border-t border-gray-100 dark:border-gray-700 space-y-2">
                        <button @click="darkMode = !darkMode; localStorage.setItem('theme', darkMode ? 'dark' : 'light'); document.documentElement.classList.toggle('dark')" 
                                class="flex items-center gap-3 px-4 py-2 text-sm font-bold text-gray-500 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700 w-full rounded-lg transition">
                            <i class="ph" :class="darkMode ? 'ph-sun' : 'ph-moon'"></i>
                            <span x-text="darkMode ? 'Light Mode' : 'Dark Mode'"></span>
                        </button>

                        <button @click="localStorage.removeItem('admin_pass'); window.location.href='/login'" 
                                class="flex items-center gap-3 px-4 py-2 text-sm font-bold text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 w-full rounded-lg transition">
                            <i class="ph ph-sign-out text-lg"></i> Logout
                        </button>
                    </div>
                </aside>

                <div x-show="sidebarOpen" @click="sidebarOpen = false" class="fixed inset-0 bg-black/50 z-40 md:hidden" x-transition.opacity></div>

                <main class="flex-1 p-4 md:p-8 ml-0 md:ml-64 mt-16 md:mt-0 transition-all">
                    ${content}
                </main>
            </div>
        `;

        // Init Dark Mode Class on HTML tag
        if (localStorage.getItem('theme') === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    }

    // Helper untuk membuat link menu aktif otomatis
    navLink(href, icon, label) {
        const current = window.location.pathname;
        const isActive = current === href || (href !== '/admin/dashboard' && current.startsWith(href));
        
        const base = "flex items-center gap-3 px-4 py-3 text-sm font-bold rounded-lg transition group";
        const activeClass = "bg-blue-50 text-blue-600 dark:bg-blue-600 dark:text-white shadow-sm";
        const inactiveClass = "text-gray-500 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-700 dark:hover:text-white";

        return `
            <a href="${href}" class="${base} ${isActive ? activeClass : inactiveClass}">
                <i class="ph ${icon} text-lg ${isActive ? '' : 'group-hover:scale-110 transition-transform'}"></i> 
                ${label}
            </a>
        `;
    }
}

customElements.define('admin-layout', AdminLayout);
