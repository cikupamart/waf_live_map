/** @odoo-module **/

import { Component, onWillStart, onWillUnmount, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { useService } from "@web/core/utils/hooks";

const REFRESH_INTERVAL_MS = 15000;

const THREAT_LABELS = {
    sql_injection: "SQL Injection",
    xss: "XSS",
    rce: "RCE / Command Injection",
    path_traversal: "Path Traversal",
    rate_limit: "Rate Limit",
    brute_force: "Brute Force Login",
    blacklisted: "Blacklisted IP",
    file_extension: "Ekstensi File Diblokir",
    other: "Lainnya",
};

export class WafDashboard extends Component {
    static template = "waf_security.Dashboard";

    setup() {
        this.rpc = useService("rpc");
        this.actionService = useService("action");
        this.state = useState({
            loading: true,
            errorMessage: "",
            total_today: 0,
            blocked_today: 0,
            critical_24h: 0,
            active_bans: 0,
            threat_breakdown: [],
        });
        this._pollTimer = null;

        onWillStart(async () => {
            await this._refresh();
            this._pollTimer = setInterval(() => this._refresh(), REFRESH_INTERVAL_MS);
        });

        onWillUnmount(() => {
            if (this._pollTimer) {
                clearInterval(this._pollTimer);
            }
        });
    }

    async _refresh() {
        try {
            const stats = await this.rpc("/waf_security/dashboard_stats", {});
            if (stats && stats.error) {
                this.state.errorMessage = "Akses ditolak: Anda tidak punya izin melihat data WAF.";
                this.state.loading = false;
                return;
            }
            this.state.total_today = stats.total_today || 0;
            this.state.blocked_today = stats.blocked_today || 0;
            this.state.critical_24h = stats.critical_24h || 0;
            this.state.active_bans = stats.active_bans || 0;

            const byThreat = stats.by_threat_24h || {};
            const maxCount = Math.max(1, ...Object.values(byThreat));
            this.state.threat_breakdown = Object.entries(byThreat)
                .sort((a, b) => b[1] - a[1])
                .map(([key, count]) => ({
                    key,
                    label: THREAT_LABELS[key] || key,
                    count,
                    pct: Math.round((count / maxCount) * 100),
                }));
            this.state.loading = false;
        } catch (e) {
            this.state.errorMessage = "Gagal mengambil statistik dashboard.";
            this.state.loading = false;
        }
    }

    openLiveMap() {
        this.actionService.doAction("waf_security.action_waf_live_attack_map");
    }

    openAuditLog() {
        this.actionService.doAction("waf_security.action_waf_log");
    }
}

registry.category("actions").add("waf_dashboard_monitoring", WafDashboard);
