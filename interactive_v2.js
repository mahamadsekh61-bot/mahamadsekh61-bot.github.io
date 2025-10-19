/**
 * PHOENIX PROTOCOL - WEBSITE 2.0 INTERACTIVE UX ENGINE
 * Constitutional Authority: Engineering Guild (Mandate 2)
 * Purpose: Scroll animations, live stats counter, theme toggle, hover effects
 * Version: 2.0 (October 2025)
 */

(function() {
    'use strict';

    // ═══════════════════════════════════════════════════════════
    // THEME TOGGLE - Dark/Light Mode Switcher
    // ═══════════════════════════════════════════════════════════

    class ThemeToggle {
        constructor() {
            this.theme = localStorage.getItem('phoenixTheme') || 'dark';
            this.init();
        }

        init() {
            // Apply saved theme
            document.documentElement.setAttribute('data-theme', this.theme);

            // Create theme toggle button if not exists
            if (!document.querySelector('.theme-toggle')) {
                this.createToggleButton();
            }

            // Attach event listener
            const toggleBtn = document.querySelector('.theme-toggle');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', () => this.toggle());
            }

            console.log('✅ Theme Toggle initialized:', this.theme);
        }

        createToggleButton() {
            const nav = document.querySelector('nav');
            if (!nav) return;

            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'theme-toggle';
            toggleBtn.setAttribute('aria-label', 'Toggle theme');
            toggleBtn.innerHTML = this.getIcon();

            nav.appendChild(toggleBtn);
        }

        toggle() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', this.theme);
            localStorage.setItem('phoenixTheme', this.theme);

            // Update button icon
            const toggleBtn = document.querySelector('.theme-toggle');
            if (toggleBtn) {
                toggleBtn.innerHTML = this.getIcon();
            }

            console.log('🎨 Theme switched to:', this.theme);
        }

        getIcon() {
            if (this.theme === 'dark') {
                // Sun icon (for switching to light mode)
                return `
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" 
                              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
                    </svg>
                `;
            } else {
                // Moon icon (for switching to dark mode)
                return `
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" 
                              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
                    </svg>
                `;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // SCROLL ANIMATIONS - Intersection Observer API
    // ═══════════════════════════════════════════════════════════

    class ScrollAnimations {
        constructor() {
            this.animatedElements = [];
            this.init();
        }

        init() {
            // Select elements to animate
            const elements = document.querySelectorAll('.feature-box, .live-stats, .email-signup');

            if (!window.IntersectionObserver) {
                // Fallback for browsers without Intersection Observer
                elements.forEach(el => el.classList.add('aos-animate'));
                console.log('⚠️  Intersection Observer not supported - animations disabled');
                return;
            }

            const observerOptions = {
                root: null,
                rootMargin: '0px',
                threshold: 0.15  // Trigger when 15% of element is visible
            };

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        // Add animation class with stagger delay
                        const delay = this.animatedElements.indexOf(entry.target) * 100;
                        setTimeout(() => {
                            entry.target.classList.add('aos-animate');
                        }, delay);

                        // Stop observing after animation
                        observer.unobserve(entry.target);
                    }
                });
            }, observerOptions);

            // Observe each element
            elements.forEach((el, index) => {
                this.animatedElements.push(el);
                observer.observe(el);
            });

            console.log(`✅ Scroll Animations initialized: ${elements.length} elements`);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // LIVE STATS COUNTER - Animated Number Counting
    // ═══════════════════════════════════════════════════════════

    class LiveStatsCounter {
        constructor() {
            this.counters = [];
            this.hasAnimated = false;
            this.init();
        }

        init() {
            const statsSection = document.querySelector('.live-stats');
            if (!statsSection) {
                console.log('ℹ️  No live stats section found - skipping counter');
                return;
            }

            // Find all stat numbers
            const statNumbers = statsSection.querySelectorAll('.stat-number');

            // Set up Intersection Observer to trigger counter
            const observerOptions = {
                root: null,
                rootMargin: '0px',
                threshold: 0.5
            };

            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting && !this.hasAnimated) {
                        this.hasAnimated = true;
                        this.animateCounters(statNumbers);
                        observer.unobserve(entry.target);
                    }
                });
            }, observerOptions);

            observer.observe(statsSection);

            console.log(`✅ Live Stats Counter initialized: ${statNumbers.length} counters`);
        }

        animateCounters(statNumbers) {
            statNumbers.forEach((el, index) => {
                const targetValue = parseInt(el.getAttribute('data-count') || el.textContent.replace(/,/g, ''));
                const duration = 2000;  // 2 seconds animation
                const startTime = Date.now() + (index * 200);  // Stagger by 200ms

                // Reset to 0
                el.textContent = '0';

                const animate = () => {
                    const now = Date.now();
                    const elapsed = now - startTime;

                    if (elapsed < 0) {
                        requestAnimationFrame(animate);
                        return;
                    }

                    if (elapsed < duration) {
                        // Easing function (easeOutExpo)
                        const progress = 1 - Math.pow(2, -10 * (elapsed / duration));
                        const currentValue = Math.floor(progress * targetValue);
                        el.textContent = this.formatNumber(currentValue);
                        requestAnimationFrame(animate);
                    } else {
                        // Final value
                        el.textContent = this.formatNumber(targetValue);
                    }
                };

                requestAnimationFrame(animate);
            });

            console.log('🔢 Counter animation started');
        }

        formatNumber(num) {
            // Add commas for thousands
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        }
    }

    // ═══════════════════════════════════════════════════════════
    // HEADER SCROLL EFFECT - Add shadow on scroll
    // ═══════════════════════════════════════════════════════════

    class HeaderScrollEffect {
        constructor() {
            this.header = document.querySelector('header');
            this.init();
        }

        init() {
            if (!this.header) return;

            window.addEventListener('scroll', () => {
                if (window.scrollY > 50) {
                    this.header.classList.add('scrolled');
                } else {
                    this.header.classList.remove('scrolled');
                }
            });

            console.log('✅ Header scroll effect initialized');
        }
    }

    // ═══════════════════════════════════════════════════════════
    // SMOOTH SCROLL FOR ANCHOR LINKS
    // ═══════════════════════════════════════════════════════════

    class SmoothScroll {
        constructor() {
            this.init();
        }

        init() {
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', (e) => {
                    const href = anchor.getAttribute('href');
                    if (href === '#') return;

                    const target = document.querySelector(href);
                    if (target) {
                        e.preventDefault();
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });

            console.log('✅ Smooth scroll initialized');
        }
    }

    // ═══════════════════════════════════════════════════════════
    // ENHANCED HOVER EFFECTS - Ripple Effect on Buttons
    // ═══════════════════════════════════════════════════════════

    class RippleEffect {
        constructor() {
            this.init();
        }

        init() {
            const buttons = document.querySelectorAll('button, .btn, input[type="submit"]');

            buttons.forEach(button => {
                button.addEventListener('click', (e) => {
                    const ripple = document.createElement('span');
                    ripple.classList.add('ripple-effect');

                    const rect = button.getBoundingClientRect();
                    const size = Math.max(rect.width, rect.height);
                    const x = e.clientX - rect.left - size / 2;
                    const y = e.clientY - rect.top - size / 2;

                    ripple.style.width = ripple.style.height = `${size}px`;
                    ripple.style.left = `${x}px`;
                    ripple.style.top = `${y}px`;

                    button.appendChild(ripple);

                    setTimeout(() => ripple.remove(), 600);
                });
            });

            // Add ripple CSS if not exists
            if (!document.querySelector('#ripple-styles')) {
                const style = document.createElement('style');
                style.id = 'ripple-styles';
                style.textContent = `
                    .ripple-effect {
                        position: absolute;
                        border-radius: 50%;
                        background: rgba(255, 255, 255, 0.5);
                        transform: scale(0);
                        animation: ripple-animation 600ms ease-out;
                        pointer-events: none;
                    }
                    @keyframes ripple-animation {
                        to {
                            transform: scale(4);
                            opacity: 0;
                        }
                    }
                `;
                document.head.appendChild(style);
            }

            console.log(`✅ Ripple effects initialized: ${buttons.length} buttons`);
        }
    }

    // ═══════════════════════════════════════════════════════════
    // FORM VALIDATION - Enhanced Email Input
    // ═══════════════════════════════════════════════════════════

    class FormValidation {
        constructor() {
            this.init();
        }

        init() {
            const emailInputs = document.querySelectorAll('input[type="email"]');

            emailInputs.forEach(input => {
                input.addEventListener('blur', () => {
                    if (input.value && !this.isValidEmail(input.value)) {
                        input.style.borderColor = 'var(--accent-danger)';
                        this.showError(input, 'Please enter a valid email address');
                    } else {
                        input.style.borderColor = 'var(--glass-border)';
                        this.removeError(input);
                    }
                });

                input.addEventListener('input', () => {
                    input.style.borderColor = 'var(--glass-border)';
                    this.removeError(input);
                });
            });

            console.log(`✅ Form validation initialized: ${emailInputs.length} email inputs`);
        }

        isValidEmail(email) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
        }

        showError(input, message) {
            this.removeError(input);
            const error = document.createElement('div');
            error.className = 'form-error';
            error.textContent = message;
            error.style.cssText = 'color: var(--accent-danger); font-size: 0.875rem; margin-top: 0.5rem;';
            input.parentElement.appendChild(error);
        }

        removeError(input) {
            const error = input.parentElement.querySelector('.form-error');
            if (error) error.remove();
        }
    }

    // ═══════════════════════════════════════════════════════════
    // PERFORMANCE MONITORING - Log Initialization
    // ═══════════════════════════════════════════════════════════

    class PerformanceMonitor {
        constructor() {
            this.startTime = performance.now();
            this.init();
        }

        init() {
            window.addEventListener('load', () => {
                const loadTime = performance.now() - this.startTime;
                console.log(`⚡ Page fully loaded in ${Math.round(loadTime)}ms`);

                // Check Core Web Vitals if available
                if ('PerformanceObserver' in window) {
                    this.observeWebVitals();
                }
            });
        }

        observeWebVitals() {
            try {
                const observer = new PerformanceObserver((list) => {
                    for (const entry of list.getEntries()) {
                        if (entry.entryType === 'largest-contentful-paint') {
                            console.log(`📊 LCP: ${Math.round(entry.renderTime || entry.loadTime)}ms`);
                        }
                    }
                });
                observer.observe({ entryTypes: ['largest-contentful-paint'] });
            } catch (e) {
                // Silently fail if not supported
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // INITIALIZATION - Execute on DOM Ready
    // ═══════════════════════════════════════════════════════════

    function init() {
        console.log('🔥 Phoenix Protocol Website 2.0 - Interactive UX Engine Starting...');

        // Initialize all features
        new ThemeToggle();
        new ScrollAnimations();
        new LiveStatsCounter();
        new HeaderScrollEffect();
        new SmoothScroll();
        new RippleEffect();
        new FormValidation();
        new PerformanceMonitor();

        console.log('✅ All interactive features initialized successfully');
        console.log('───────────────────────────────────────────────────────');
        console.log('Features Active:');
        console.log('  ✓ Theme Toggle (Dark/Light)');
        console.log('  ✓ Scroll Animations (Intersection Observer)');
        console.log('  ✓ Live Stats Counter (Animated)');
        console.log('  ✓ Header Scroll Effect');
        console.log('  ✓ Smooth Scroll');
        console.log('  ✓ Button Ripple Effects');
        console.log('  ✓ Form Validation');
        console.log('  ✓ Performance Monitoring');
        console.log('───────────────────────────────────────────────────────');
    }

    // Execute when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
