"""
Progress tracking for scan operations
Enables real-time progress updates via SSE
"""

import threading
import time
from typing import Dict, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum


class ScanPhase(Enum):
    INITIALIZING = "initializing"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    PENTESTING = "pentesting"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class ScanProgress:
    """Progress state for a scan operation"""
    scan_id: str
    phase: ScanPhase = ScanPhase.INITIALIZING
    url: str = ""

    # Crawl progress
    urls_discovered: int = 0
    urls_to_scan: int = 0

    # Scan progress
    current_url: str = ""
    current_url_index: int = 0
    total_urls: int = 1

    # Vulnerability progress
    vulns_found: int = 0

    # Current scanner
    current_scanner: str = ""

    # Pentest progress
    pentest_current: int = 0
    pentest_total: int = 0
    pentest_confirmed: int = 0
    pentest_technique: str = ""

    # Analysis progress
    analysis_step: str = ""

    # Timing
    elapsed_seconds: float = 0.0

    # Error info
    error_message: str = ""

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase.value,
            "url": self.url,
            "urls_discovered": self.urls_discovered,
            "urls_to_scan": self.urls_to_scan,
            "current_url": self.current_url,
            "current_url_index": self.current_url_index,
            "total_urls": self.total_urls,
            "vulns_found": self.vulns_found,
            "current_scanner": self.current_scanner,
            "pentest_current": self.pentest_current,
            "pentest_total": self.pentest_total,
            "pentest_confirmed": self.pentest_confirmed,
            "pentest_technique": self.pentest_technique,
            "analysis_step": self.analysis_step,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
            "error_message": self.error_message
        }


class ProgressManager:
    """Thread-safe progress manager for scan operations"""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._progress: Dict[str, ScanProgress] = {}
        self._callbacks: Dict[str, list] = {}
        self._start_times: Dict[str, float] = {}
        self._initialized = True

    def create_scan(self, scan_id: str, url: str) -> ScanProgress:
        """Create a new scan progress tracker"""
        progress = ScanProgress(scan_id=scan_id, url=url)
        self._progress[scan_id] = progress
        self._start_times[scan_id] = time.time()
        self._callbacks[scan_id] = []
        return progress

    def get_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get current progress for a scan"""
        progress = self._progress.get(scan_id)
        if progress and scan_id in self._start_times:
            progress.elapsed_seconds = time.time() - self._start_times[scan_id]
        return progress

    def update(self, scan_id: str, **kwargs):
        """Update progress and notify callbacks"""
        progress = self._progress.get(scan_id)
        if not progress:
            return

        for key, value in kwargs.items():
            if hasattr(progress, key):
                setattr(progress, key, value)

        # Update elapsed time
        if scan_id in self._start_times:
            progress.elapsed_seconds = time.time() - self._start_times[scan_id]

        # Notify callbacks
        self._notify(scan_id)

    def set_phase(self, scan_id: str, phase: ScanPhase, **kwargs):
        """Update scan phase and optionally other fields"""
        self.update(scan_id, phase=phase, **kwargs)

    def add_callback(self, scan_id: str, callback: Callable):
        """Add a callback to be notified of progress updates"""
        if scan_id in self._callbacks:
            self._callbacks[scan_id].append(callback)

    def remove_callback(self, scan_id: str, callback: Callable):
        """Remove a callback"""
        if scan_id in self._callbacks:
            try:
                self._callbacks[scan_id].remove(callback)
            except ValueError:
                pass

    def _notify(self, scan_id: str):
        """Notify all callbacks of progress update"""
        if scan_id not in self._callbacks:
            return

        progress = self._progress.get(scan_id)
        if not progress:
            return

        for callback in self._callbacks[scan_id]:
            try:
                callback(progress)
            except Exception:
                pass

    def cleanup(self, scan_id: str):
        """Remove progress tracker for completed scan"""
        self._progress.pop(scan_id, None)
        self._callbacks.pop(scan_id, None)
        self._start_times.pop(scan_id, None)


def get_progress_manager() -> ProgressManager:
    """Get the singleton progress manager"""
    return ProgressManager()
