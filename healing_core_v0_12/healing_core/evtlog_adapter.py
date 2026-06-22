"""
healing_core.evtlog_adapter
────────────────────────────
WindowsEvtLogAdapter — polls Windows Event Log channels and converts
EVTX records into healing_core Event objects fed to HealingCore.ingest().

No pywin32 dependency required — uses stdlib subprocess + wevtutil.exe.
If pywin32 IS installed, uses win32evtlog for lower latency.

Design:
  • Background thread polls each channel every poll_interval seconds
  • Tracks last RecordId per channel to avoid re-processing
  • XML records parsed with stdlib xml.etree.ElementTree
  • Rate-limited: max_events_per_poll guards against log storms
  • Severity mapping: Critical/Error → HIGH, Warning → MEDIUM, Info → LOW
  • EventID embedded in error_type as "EventID_NNNN"
  • Source (Provider) embedded in actor
  • Channel embedded in subsystem
  • Graceful fallback when wevtutil not found (Windows only anyway)

Usage:
    adapter = WindowsEvtLogAdapter(core, channels=["System","Security"])
    adapter.start()
    ...
    adapter.stop()
"""
from __future__ import annotations

import logging
import platform
import queue
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import HealingCore

from .models import Event

# Optional pywin32 fast-path (lower latency than wevtutil subprocess)
try:
    import win32evtlog, win32evtlogutil, win32con, pywintypes
    _PYWIN32 = True
except ImportError:
    _PYWIN32 = False


log = logging.getLogger("healing_core.evtlog_adapter")

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Windows Event Log severity levels → our convention
_LEVEL_MAP = {
    "0": "critical",   # Log Always
    "1": "critical",   # Critical
    "2": "error",      # Error
    "3": "warning",    # Warning
    "4": "info",       # Information
    "5": "verbose",    # Verbose
}

# Event IDs we care about across channels (empty = all)
DEFAULT_INTERESTING_IDS = {
    # System
    41, 7, 11, 51, 129,                         # hardware/disk
    7000, 7001, 7003, 7009, 7011, 7023, 7024,   # service start/timeout
    7026, 7029, 7031, 7034, 7035, 7036, 7038,   # service crash/state
    2004, 2013, 2019, 2020,                      # resource exhaustion
    1001, 1003,                                  # BSOD / crash dump
    # Security
    4625, 4740, 4771, 4776, 4648,               # auth failures / lockout
    4697, 4698, 4673, 4674, 4688, 4725, 4738,   # privilege / account
    1102,                                        # audit log cleared
    # Application
    1000, 1001, 1002, 7045,                      # app crash / new service
    10016,                                       # DCOM
}


class WindowsEvtLogAdapter:
    """Polls Windows Event Log and feeds events to HealingCore."""

    DEFAULT_CHANNELS = ["System", "Application", "Security"]

    def __init__(
        self,
        core: "HealingCore",
        channels: Optional[List[str]] = None,
        poll_interval: float = 10.0,
        max_events_per_poll: int = 50,
        interesting_ids: Optional[set] = None,
        lookback_events: int = 10,          # records to read on first poll
        prefer_native:   bool = True,        # use pywin32 if available
    ) -> None:
        self._core        = core
        self._channels    = channels or self.DEFAULT_CHANNELS
        self._interval    = poll_interval
        self._max_events  = max_events_per_poll
        self._ids         = interesting_ids or DEFAULT_INTERESTING_IDS
        self._lookback    = lookback_events
        self._prefer_native = prefer_native and _PYWIN32
        self._last_id:    Dict[str, int] = {}   # channel → last RecordId seen
        self._stop        = threading.Event()
        self._thread:     Optional[threading.Thread] = None
        self._queue:      queue.Queue = queue.Queue(maxsize=500)
        self._ingest_thread: Optional[threading.Thread] = None
        self._ingested    = 0
        self._errors      = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if platform.system() != "Windows":
            log.warning("evtlog_adapter | not on Windows, adapter is a no-op")
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, name="evtlog-poll", daemon=True)
        self._ingest_thread = threading.Thread(
            target=self._ingest_loop, name="evtlog-ingest", daemon=True)
        self._thread.start()
        self._ingest_thread.start()
        log.info("evtlog_adapter | started  channels=%s  interval=%.0fs",
                 self._channels, self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        if self._ingest_thread:
            self._ingest_thread.join(timeout=5)
        log.info("evtlog_adapter | stopped  ingested=%d  errors=%d",
                 self._ingested, self._errors)

    def stats(self) -> dict:
        return {
            "channels":  self._channels,
            "ingested":  self._ingested,
            "errors":    self._errors,
            "queue_len": self._queue.qsize(),
        }

    # ── Poll loop ──────────────────────────────────────────────────────────

    def _poll_loop(self) -> None:
        while not self._stop.is_set():
            for channel in self._channels:
                try:
                    self._poll_channel(channel)
                except Exception as exc:
                    log.debug("evtlog_adapter | poll error channel=%s: %s", channel, exc)
                    self._errors += 1
            self._stop.wait(self._interval)

    def _poll_channel(self, channel: str) -> None:
        if self._prefer_native:
            self._poll_channel_native(channel)
        else:
            self._poll_channel_wevtutil(channel)

    def _poll_channel_native(self, channel: str) -> None:
        """pywin32 fast-path: real-time notification via ReadEventLog."""
        try:
            flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            h = win32evtlog.OpenEventLog(None, channel)
            last = self._last_id.get(channel, 0)  # wevtutil path
            records = win32evtlog.ReadEventLog(h, flags, 0)
            win32evtlog.CloseEventLog(h)
            for rec in reversed(records):
                rid = rec.RecordNumber
                if rid <= last:
                    continue
                eid = rec.EventID & 0xFFFF
                if self._ids and eid not in self._ids:
                    continue
                # Level: EventType 1=Error 2=Warning 4=Info 8=AuditSuccess 16=AuditFail
                etype = rec.EventType
                if etype not in (win32con.EVENTLOG_ERROR_TYPE,
                                 win32con.EVENTLOG_WARNING_TYPE,
                                 win32con.EVENTLOG_AUDIT_FAILURE):
                    continue
                try:
                    msg = win32evtlogutil.SafeFormatMessage(rec, channel)
                except Exception:
                    msg = f"EventID {eid}"
                provider = rec.SourceName or channel
                evt = Event(
                    error_type = f"EventID_{eid}",
                    message    = f"EventID {eid}: {(msg or '')[:400]}",
                    actor      = provider,
                    subsystem  = channel,
                )
                if rid > self._last_id.get(channel, 0):
                    self._last_id[channel] = rid
                try:
                    self._queue.put_nowait(evt)
                except Exception:
                    pass
        except Exception as exc:
            log.debug("evtlog_adapter | pywin32 poll error channel=%s: %s", channel, exc)
            # Fall back to wevtutil for this poll
            self._poll_channel_wevtutil(channel)

    def _poll_channel_wevtutil(self, channel: str) -> None:
        last = self._last_id.get(channel, 0)
        if last == 0:
            # First poll — read recent records only
            query = f"*[System[TimeCreated[timediff(@SystemTime) <= 300000]]]"
        else:
            query = f"*[System[EventRecordID > {last}]]"

        cmd = [
            "wevtutil", "qe", channel,
            f"/q:{query}",
            f"/c:{self._max_events}",
            "/f:xml",
            "/rd:false",   # oldest first
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.debug("evtlog_adapter | wevtutil error: %s", exc)
            return

        if result.returncode != 0:
            return

        xml_text = result.stdout.strip()
        if not xml_text:
            return

        # wevtutil returns multiple <Event> elements — wrap in root
        try:
            root = ET.fromstring(f"<Events>{xml_text}</Events>")
        except ET.ParseError:
            # Try individual elements
            root = ET.Element("Events")
            for block in re.split(r"(?=<Event )", xml_text):
                if not block.strip():
                    continue
                try:
                    root.append(ET.fromstring(block))
                except ET.ParseError:
                    pass

        for elem in root:
            evt = self._xml_to_event(elem, channel)
            if evt is None:
                continue
            # Update last seen record id
            rid = self._get_record_id(elem)
            if rid and rid > self._last_id.get(channel, 0):
                self._last_id[channel] = rid
            # Enqueue without blocking
            try:
                self._queue.put_nowait(evt)
            except queue.Full:
                log.debug("evtlog_adapter | queue full, dropping event")

    # ── Ingest loop ────────────────────────────────────────────────────────

    def _ingest_loop(self) -> None:
        while not self._stop.is_set():
            try:
                evt = self._queue.get(timeout=2.0)
                try:
                    self._core.ingest(evt)
                    self._ingested += 1
                except Exception as exc:
                    log.debug("evtlog_adapter | ingest error: %s", exc)
                    self._errors += 1
            except queue.Empty:
                pass

    # ── XML → Event conversion ─────────────────────────────────────────────

    def _xml_to_event(self, elem: ET.Element, channel: str) -> Optional[Event]:
        try:
            sys_el  = elem.find("e:System", _NS)
            if sys_el is None:
                return None

            event_id_el = sys_el.find("e:EventID", _NS)
            if event_id_el is None:
                return None
            event_id = int(event_id_el.text or "0")

            # Filter to interesting IDs if set is non-empty
            if self._ids and event_id not in self._ids:
                return None

            level_el = sys_el.find("e:Level", _NS)
            level    = _LEVEL_MAP.get(
                (level_el.text or "4").strip(), "info")

            # Skip verbose/info unless we explicitly want them
            if level in ("info", "verbose") and event_id not in self._ids:
                return None

            provider_el = sys_el.find("e:Provider", _NS)
            provider    = ""
            if provider_el is not None:
                provider = (provider_el.get("Name") or
                            provider_el.get("EventSourceName") or "")

            # Build human-readable message from EventData / UserData
            message = self._extract_message(elem, event_id)
            if not message:
                message = f"EventID {event_id} from {provider}"
            else:
                message = f"EventID {event_id}: {message}"

            return Event(
                error_type = f"EventID_{event_id}",
                message    = message[:512],
                actor      = provider or channel,
                subsystem  = channel,
            )

        except Exception as exc:
            log.debug("evtlog_adapter | xml parse error: %s", exc)
            return None

    def _extract_message(self, elem: ET.Element, event_id: int) -> str:
        parts = []
        for container in ("e:EventData", "e:UserData"):
            data_el = elem.find(container, _NS)
            if data_el is None:
                continue
            for child in data_el.iter():
                if child.text and child.text.strip():
                    name = child.get("Name", child.tag.split("}")[-1])
                    parts.append(f"{name}={child.text.strip()}")
        return "; ".join(parts[:8])   # cap at 8 fields

    def _get_record_id(self, elem: ET.Element) -> Optional[int]:
        sys_el = elem.find("e:System", _NS)
        if sys_el is None:
            return None
        rid_el = sys_el.find("e:EventRecordID", _NS)
        if rid_el is not None and rid_el.text:
            try:
                return int(rid_el.text)
            except ValueError:
                pass
        return None
