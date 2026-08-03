/** @odoo-module **/

import { Component, onWillStart, onMounted, onWillUnmount, useRef, useState } from "@odoo/owl";
import { registry } from "@web/core/registry";
import { loadJS, loadCSS } from "@web/core/assets";
import { useService } from "@web/core/utils/hooks";

// CATATAN IMPLEMENTASI:
// Widget ini memuat Leaflet.js (library peta open-source, BSD-2-Clause
// license) dari CDN saat komponen pertama kali dibuka - bukan di-bundle ke
// modul, supaya ukuran modul tetap kecil. Konsekuensinya: fitur ini butuh
// akses internet dari BROWSER user (bukan dari server Odoo) untuk memuat
// leaflet.js/css serta ubin peta (map tiles) dari OpenStreetMap. Kalau
// instance Anda dipakai di jaringan tertutup tanpa akses internet, peta
// tidak akan muncul (tapi fitur WAF lainnya tetap berfungsi normal).
const LEAFLET_JS = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.js";
const LEAFLET_CSS = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";

const SEVERITY_COLOR = {
    critical: "#dc3545",
    high: "#fd7e14",
    medium: "#ffc107",
    low: "#6c757d",
};

const REFRESH_INTERVAL_MS = 8000; // polling, bukan websocket - cukup untuk kebutuhan belajar

export class WafLiveAttackMap extends Component {
    static template = "waf_security.LiveAttackMap";

    setup() {
        this.rpc = useService("rpc");
        this.mapRef = useRef("mapContainer");
        this.state = useState({
            loading: true,
            leafletReady: false,
            errorMessage: "",
            attackCount: 0,
            lastUpdate: "",
            geoipEnabled: true,
        });
        this._map = null;
        this._markersLayer = null;
        this._pollTimer = null;
        this._knownIds = new Set();

        onWillStart(async () => {
            try {
                await loadCSS(LEAFLET_CSS);
                await loadJS(LEAFLET_JS);
                this.state.leafletReady = true;
            } catch (e) {
                this.state.errorMessage =
                    "Gagal memuat library peta (Leaflet) dari CDN. " +
                    "Pastikan browser Anda punya akses internet.";
            }
        });

        onMounted(() => {
            if (this.state.leafletReady) {
                this._initMap();
                this._refresh();
                this._pollTimer = setInterval(() => this._refresh(), REFRESH_INTERVAL_MS);
            }
        });

        onWillUnmount(() => {
            if (this._pollTimer) {
                clearInterval(this._pollTimer);
            }
        });
    }

    _initMap() {
        // eslint-disable-next-line no-undef
        const L = window.L;
        if (!L || !this.mapRef.el) {
            return;
        }
        this._map = L.map(this.mapRef.el, {
            worldCopyJump: true,
            minZoom: 2,
        }).setView([15, 20], 2);

        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            attribution: "&copy; OpenStreetMap contributors",
            maxZoom: 18,
        }).addTo(this._map);

        this._markersLayer = L.layerGroup().addTo(this._map);
    }

    async _refresh() {
        try {
            const result = await this.rpc("/waf_security/live_attack_feed", { minutes: 60, limit: 200 });
            if (result && result.error) {
                this.state.errorMessage = "Akses ditolak: Anda tidak punya izin melihat data WAF.";
                return;
            }
            const attacks = (result && result.attacks) || [];
            this.state.geoipEnabled = result ? !!result.geoip_enabled : true;
            this.state.attackCount = attacks.length;
            this.state.lastUpdate = new Date().toLocaleTimeString();
            this.state.loading = false;
            this._renderMarkers(attacks);
        } catch (e) {
            this.state.errorMessage = "Gagal mengambil data serangan terbaru.";
        }
    }

    _renderMarkers(attacks) {
        // eslint-disable-next-line no-undef
        const L = window.L;
        if (!L || !this._markersLayer) {
            return;
        }
        for (const attack of attacks) {
            if (this._knownIds.has(attack.id)) {
                continue; // sudah pernah digambar, jangan duplikat marker
            }
            this._knownIds.add(attack.id);
            if (!attack.lat && !attack.lon) {
                continue;
            }
            const color = SEVERITY_COLOR[attack.severity] || SEVERITY_COLOR.low;
            const marker = L.circleMarker([attack.lat, attack.lon], {
                radius: 7,
                color: color,
                fillColor: color,
                fillOpacity: 0.75,
                weight: 2,
            });
            const popupHtml =
                `<strong>${this._escape(attack.ip)}</strong> ` +
                `(${this._escape(attack.city)}${attack.city ? ", " : ""}${this._escape(attack.country)})<br/>` +
                `Ancaman: ${this._escape(attack.threat_type)}<br/>` +
                `Severity: ${this._escape(attack.severity)}<br/>` +
                `Tindakan: ${this._escape(attack.action_taken)}<br/>` +
                `URL: ${this._escape(attack.url)}<br/>` +
                `Waktu: ${this._escape(attack.time)}`;
            marker.bindPopup(popupHtml);
            marker.addTo(this._markersLayer);
        }
    }

    _escape(text) {
        if (!text) {
            return "";
        }
        const div = document.createElement("div");
        div.textContent = String(text);
        return div.innerHTML;
    }
}

registry.category("actions").add("waf_live_attack_map", WafLiveAttackMap);
