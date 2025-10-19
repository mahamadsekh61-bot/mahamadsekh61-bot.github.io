/**
 * ASRE (Autonomous Self-Repair Engine)
 * Constitutional monitoring and self-healing for Phoenix Protocol web presence
 * Mandate 1 + Pillar 3 (Honest State Awareness)
 */

class ASREEngine {
    constructor() {
        this.healthChecks = [];
        this.repairActions = [];
        this.metrics = {
            checks_performed: 0,
            repairs_executed: 0,
            uptime_start: Date.now()
        };
        this.config = {
            check_interval_ms: 30000, // 30 seconds
            critical_threshold: 3, // Max failed checks before repair
            log_to_console: true
        };
    }

    /**
     * Register a health check function
     * @param {string} name - Check identifier
     * @param {Function} checkFn - Function returning {healthy: boolean, details: string}
     * @param {Function} repairFn - Function to execute if check fails
     */
    registerCheck(name, checkFn, repairFn) {
        this.healthChecks.push({
            name,
            checkFn,
            repairFn,
            failures: 0,
            last_check: null,
            last_status: null
        });
    }

    /**
     * Execute all health checks
     */
    async runHealthChecks() {
        this.metrics.checks_performed++;
        const results = [];

        for (const check of this.healthChecks) {
            try {
                const result = await check.checkFn();
                check.last_check = Date.now();
                check.last_status = result.healthy ? 'pass' : 'fail';

                if (!result.healthy) {
                    check.failures++;
                    this.log('warn', `Health check failed: ${check.name}`, result.details);

                    // Execute repair if threshold exceeded
                    if (check.failures >= this.config.critical_threshold && check.repairFn) {
                        this.log('info', `Executing repair for: ${check.name}`);
                        await check.repairFn();
                        this.metrics.repairs_executed++;
                        check.failures = 0; // Reset after repair
                    }
                } else {
                    check.failures = 0; // Reset on success
                }

                results.push({
                    name: check.name,
                    healthy: result.healthy,
                    details: result.details,
                    failures: check.failures
                });
            } catch (error) {
                this.log('error', `Health check error: ${check.name}`, error.message);
                results.push({
                    name: check.name,
                    healthy: false,
                    details: `Exception: ${error.message}`,
                    failures: check.failures
                });
            }
        }

        return results;
    }

    /**
     * Start continuous monitoring
     */
    startMonitoring() {
        this.log('info', 'ASRE Engine started - Constitutional monitoring active');
        
        // Initial check
        this.runHealthChecks();

        // Periodic checks
        this.monitoringInterval = setInterval(() => {
            this.runHealthChecks();
        }, this.config.check_interval_ms);

        return this;
    }

    /**
     * Stop monitoring
     */
    stopMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.log('info', 'ASRE Engine stopped');
        }
    }

    /**
     * Get current system health status
     */
    getHealthStatus() {
        const total_checks = this.healthChecks.length;
        const passing = this.healthChecks.filter(c => c.last_status === 'pass').length;
        const failing = this.healthChecks.filter(c => c.last_status === 'fail').length;
        const uptime_hours = (Date.now() - this.metrics.uptime_start) / (1000 * 60 * 60);

        return {
            healthy: failing === 0,
            total_checks,
            passing,
            failing,
            uptime_hours: uptime_hours.toFixed(2),
            metrics: this.metrics
        };
    }

    /**
     * Logging utility
     */
    log(level, message, details = '') {
        if (!this.config.log_to_console) return;

        const timestamp = new Date().toISOString();
        const prefix = {
            info: '✓',
            warn: '⚠',
            error: '✗'
        }[level] || '•';

        console.log(`[${timestamp}] ${prefix} ASRE: ${message}`, details ? `\n   ${details}` : '');
    }
}

// Phoenix Protocol Specific Health Checks
const phoenixASRE = new ASREEngine();

// Check 1: Email form endpoint validation
phoenixASRE.registerCheck(
    'formspree_endpoint',
    async () => {
        const form = document.querySelector('form[action*="formspree"]');
        if (!form) {
            return { healthy: false, details: 'Email form not found in DOM' };
        }
        
        const action = form.getAttribute('action');
        if (action.includes('YOUR_FORM_ID') || action.includes('placeholder')) {
            return { healthy: false, details: 'Placeholder form endpoint detected' };
        }

        return { healthy: true, details: 'Email capture operational' };
    },
    () => {
        console.error('CRITICAL: Email form misconfigured. Manual intervention required.');
        // Log to analytics or send alert
    }
);

// Check 2: Critical content presence
phoenixASRE.registerCheck(
    'critical_content',
    async () => {
        const criticalElements = [
            { selector: 'h1', name: 'Main headline' },
            { selector: 'form', name: 'Email capture form' },
            { selector: '.lead-magnet', name: 'Value proposition' }
        ];

        for (const element of criticalElements) {
            if (!document.querySelector(element.selector)) {
                return { 
                    healthy: false, 
                    details: `Missing critical element: ${element.name}` 
                };
            }
        }

        return { healthy: true, details: 'All critical content present' };
    },
    () => {
        console.error('CRITICAL: Page structure compromised. Check DOM integrity.');
    }
);

// Check 3: CSS/Style integrity
phoenixASRE.registerCheck(
    'style_integrity',
    async () => {
        const testElement = document.querySelector('body');
        if (!testElement) {
            return { healthy: false, details: 'Body element not found' };
        }

        const styles = window.getComputedStyle(testElement);
        const hasBackground = styles.background !== 'rgba(0, 0, 0, 0)';
        
        if (!hasBackground) {
            return { healthy: false, details: 'CSS may not be loaded' };
        }

        return { healthy: true, details: 'Styles applied correctly' };
    },
    () => {
        console.warn('Style integrity check failed. CSS may be corrupted.');
    }
);

// Check 4: External link validation (blog, docs)
phoenixASRE.registerCheck(
    'navigation_links',
    async () => {
        const links = document.querySelectorAll('a[href]');
        const brokenLinks = [];

        for (const link of links) {
            const href = link.getAttribute('href');
            if (href.startsWith('#') || href.startsWith('mailto:')) continue;
            
            // Check for common broken patterns
            if (href.includes('undefined') || href === '' || href === '#') {
                brokenLinks.push(href);
            }
        }

        if (brokenLinks.length > 0) {
            return { 
                healthy: false, 
                details: `Found ${brokenLinks.length} broken links` 
            };
        }

        return { healthy: true, details: 'All navigation links valid' };
    },
    () => {
        console.warn('Broken navigation links detected. Check link integrity.');
    }
);

// Check 5: Performance monitoring
phoenixASRE.registerCheck(
    'page_performance',
    async () => {
        if (!window.performance) {
            return { healthy: true, details: 'Performance API not available' };
        }

        const navigation = performance.getEntriesByType('navigation')[0];
        if (!navigation) {
            return { healthy: true, details: 'Navigation timing not available' };
        }

        const loadTime = navigation.loadEventEnd - navigation.fetchStart;
        const threshold_ms = 3000; // 3 seconds

        if (loadTime > threshold_ms) {
            return { 
                healthy: false, 
                details: `Page load time ${(loadTime/1000).toFixed(2)}s exceeds ${threshold_ms/1000}s threshold` 
            };
        }

        return { 
            healthy: true, 
            details: `Load time: ${(loadTime/1000).toFixed(2)}s` 
        };
    },
    () => {
        console.warn('Page performance degraded. Optimize assets or check CDN.');
    }
);

// Auto-start monitoring when DOM is ready
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            phoenixASRE.startMonitoring();
        });
    } else {
        phoenixASRE.startMonitoring();
    }
}

// Expose for manual interaction
if (typeof window !== 'undefined') {
    window.phoenixASRE = phoenixASRE;
    
    // Add status display command
    window.phoenixHealth = () => {
        const status = phoenixASRE.getHealthStatus();
        console.log('🏛️ Phoenix Protocol Health Status:', status);
        return status;
    };
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ASREEngine, phoenixASRE };
}
