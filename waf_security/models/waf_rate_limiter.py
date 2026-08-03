# -*- coding: utf-8 -*-
"""
Rate Limiter & Brute Force Tracker
====================================
Implementasi sederhana berbasis in-memory dictionary + threading.Lock.

CATATAN PEMBELAJARAN:
Pendekatan in-memory ini bekerja per-proses. Jika Odoo dijalankan dengan
beberapa worker (multi-processing, workers > 0 di odoo.conf), setiap
worker punya memori terpisah sehingga counter TIDAK dibagi antar worker.
Untuk skenario production dengan banyak worker, counter sebaiknya
disimpan di store terpusat seperti Redis. Untuk keperluan belajar/single
worker (misal saat development), pendekatan ini sudah cukup untuk
memahami konsepnya.
"""

import threading
import time
from collections import defaultdict, deque


class _SlidingWindowTracker:
    """Melacak timestamp kejadian (request/login gagal) per key (biasanya IP)
    menggunakan sliding window sederhana berbasis deque."""

    def __init__(self):
        self._lock = threading.Lock()
        self._events = defaultdict(deque)

    def hit(self, key, window_seconds):
        """Catat satu kejadian untuk `key` dan kembalikan jumlah kejadian
        dalam window waktu (detik) terakhir."""
        now = time.time()
        with self._lock:
            dq = self._events[key]
            dq.append(now)
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
        return count

    def count(self, key, window_seconds):
        now = time.time()
        with self._lock:
            dq = self._events.get(key, deque())
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def reset(self, key):
        with self._lock:
            if key in self._events:
                del self._events[key]

    def cleanup(self, max_age_seconds=3600):
        """Bersihkan entry yang sudah lama tidak aktif agar memori tidak membengkak."""
        now = time.time()
        with self._lock:
            keys_to_delete = []
            for key, dq in self._events.items():
                cutoff = now - max_age_seconds
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if not dq:
                    keys_to_delete.append(key)
            for key in keys_to_delete:
                del self._events[key]


# Instance global (module-level singleton) - dibagi oleh semua request
# dalam proses worker yang sama.
request_tracker = _SlidingWindowTracker()
login_failure_tracker = _SlidingWindowTracker()
threat_violation_tracker = _SlidingWindowTracker()
