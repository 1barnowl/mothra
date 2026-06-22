"""healing_core.classification — multi-signal rule-based incident classifier.

v0.8: Windows Event IDs, HRESULT, Win32 error codes, stop codes added.
Rule ordering: most specific / highest-priority categories first.
Word boundaries on all EventID patterns prevent cross-match (e.g., 7 vs 7034).
"""
from __future__ import annotations
import re, logging
from .models import Event, IncidentCategory

log = logging.getLogger("healing_core.classification")

_RULES = [

    # ── Malware (highest specificity — always first) ───────────────────────────
    (IncidentCategory.MALWARE,
     r"ransomware|rootkit|trojan|malware|virus|cryptolocker"
     r"|encrypt.*data|suspicious.process|rogue.process"
     r"|EventID.?1116\b|EventID.?1117\b"           # Defender threat detected
     r"|MALWAREPROTECTION_STATE|Defender.*[Tt]hreat"
     r"|Windows.Defender.*detect|WinDefend.*threat"
     r"|HEUR:|Trojan\.|Ransom\.|Virus\.|Backdoor\."
     r"|vssadmin.*delete.*shadows|shadow.*copy.*deleted"
     r"|EventID.?1102\b"                            # audit log cleared = indicator
     r"|EventID.?7045\b"),                          # new service installed

    # ── Security ──────────────────────────────────────────────────────────────
    (IncidentCategory.SECURITY,
     r"unauthorized|injection|privilege.escal|brute.force|intrusion"
     r"|anomalous.login|lateral.movement|pass.the.hash|mimikatz"
     r"|credential.dump|SECURITY_BREACH|integrity.violation|tampering"
     r"|EventID.?4697\b|EventID.?4698\b"            # scheduled task / service install
     r"|EventID.?4673\b|EventID.?4674\b"            # sensitive privilege use
     r"|EventID.?10016\b"                            # DCOM access denied
     r"|EventID.?4688\b.*(?:cmd|powershell|wscript|cscript|mshta)"
     r"|0x80070005.*(?:DCOM|dcom|access.*denied)"
     r"|firewall.block"),

    # ── Authentication ────────────────────────────────────────────────────────
    (IncidentCategory.AUTHENTICATION,
     r"auth.*fail|login.fail|invalid.cred|token.expir|certificate.expir"
     r"|oauth|kerberos|lockout|permission.denied"
     r"|EventID.?4625\b|EventID.?4740\b"            # logon failure, account lockout
     r"|EventID.?4771\b|EventID.?4776\b"            # Kerberos, NTLM
     r"|EventID.?4648\b|EventID.?4624\b"            # explicit creds, logon
     r"|EventID.?4725\b|EventID.?4738\b"            # account disabled/changed
     r"|EventID.?7038\b"                             # service logon failure
     r"|NtlmErr|KDC_ERR|KRB5KDC|Kerberos.*error"
     r"|0x8009.*cert|CERT_E_|SEC_E_LOGON_DENIED|SEC_E_NO_CREDENTIALS"
     r"|CERT_E_EXPIRED|CERT_E_UNTRUSTEDROOT|CRYPT_E_REVOKED"
     r"|SEC_E_CERT_EXPIRED|certificate.*expired|certificate.*revoked"
     r"|401 Unauthorized|403 Forbidden"
     r"|SeServiceLogonRight|account.*locked|password.*expired"
     r"|oauth.*token.*fail|refresh.token.*fail"),

    # ── Network ───────────────────────────────────────────────────────────────
    (IncidentCategory.NETWORK,
     r"wifi|wi-fi|wlan|ssid|dhcp|dns.fail|resolv"
     r"|name.resolut|no.connect|network.down|netsh|winsock"
     r"|gateway.*unreachable|no.route.to.host"
     r"|EventID.?4198\b|EventID.?4199\b"            # IP conflict
     r"|EventID.?5157\b|EventID.?5159\b"            # Filtering Platform
     r"|EventID.?1014\b"                             # DNS
     r"|EventID.?11001\b|EventID.?11002\b"           # WLAN
     r"|WSAENETUNREACH|WSAEHOSTUNREACH|WSAETIMEDOUT"
     r"|WSAECONNRESET|WSAECONNREFUSED|WSAEADDRINUSE|WSAENETRESET"
     r"|WSAECONNABORTED"
     r"|0x8007274c|0x80072751|0x80072ee2"            # WinHTTP errors
     r"|0x800706ba|WinError.?1722|RPC.*server.*unavailable"
     r"|ERR_NAME_NOT_RESOLVED|ERR_CONNECTION_REFUSED|ERR_TIMED_OUT"
     r"|port.*conflict|address.*in.use|bind.*fail|connection.*refused"
     r"|packet.loss|latency.spike|bandwidth.saturat|nat.fail|proxy.error"
     r"|winsock.*corrupt|winsock.*catalog"),

    # ── Driver (before HARDWARE to catch driver-specific event IDs) ───────────
    (IncidentCategory.DRIVER,
     r"driver.*incompatib|outdated.driver"
     r"|EventID.?219\b"                              # device conflict
     r"|EventID.?7026\b"                             # driver load fail
     r"|Code\s+10\b|Code\s+43\b|Code\s+28\b"       # Device Manager error codes
     r"|device cannot start|pnputil"
     r"|\.sys.*crash|\.sys.*exception"
     r"|DRIVER_IRQL|DRIVER_POWER_STATE|PAGE_FAULT.*driver"
     r"|driver.*conflict|driver.*fail.*load"),

    # ── Hardware ──────────────────────────────────────────────────────────────
    (IncidentCategory.HARDWARE,
     r"thermal|overheating|cpu.temp|disk.crash|raid.degrad|hardware.fail"
     r"|sensor|bios|uefi|bad.sector|S\.M\.A\.R\.T|SMART.*fail"
     r"|EventID.?41\b"                               # unexpected shutdown
     r"|EventID.?1001\b.*bugcheck|EventID.?1003\b"  # BSOD / crash dump
     r"|EventID.?7\b.*(?:disk|harddisk|controller)"  # disk controller (word boundary)
     r"|EventID.?11\b.*(?:disk|harddisk|controller)" # driver controller error
     r"|EventID.?51\b.*(?:disk|paging)"              # paging error
     r"|EventID.?129\b"                              # disk reset
     r"|BUGCHECK|STOP.?0x|0x0000007E|0x0000007F"
     r"|0x00000050|0x0000001E|0x0000003B"
     r"|0x000000EF|0x000000D1|0x000000C5"
     r"|BlueScreen|BSOD|kernel.panic|physical.memory.dump"
     r"|disk.*error|read.*error.*sector|write.*error.*sector"
     r"|battery.*fail|UPS.*disconnect|voltage.*fluctuat"),

    # ── Configuration ─────────────────────────────────────────────────────────
    (IncidentCategory.CONFIGURATION,
     r"config.*corrupt|config.*invalid|misconfigur|registry.damage"
     r"|env.var|path.misconfigur|yaml.*error|json.*error"
     r"|EventID.?4657\b|EventID.?4660\b|EventID.?4670\b" # registry modify/delete
     r"|EventID.?1000\b.*config|EventID.?1001\b.*config"
     r"|HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER"
     r"|reg.*corrupt|registry.*fail|registry.*invalid"
     r"|AppData.*corrupt|SoftwareDistribution.*corrupt"
     r"|0x80070003|0x80070002"                       # path/file not found
     r"|0x80070005(?!.*DCOM)"                        # access denied (non-DCOM)
     r"|WinError.?2\b|WinError.?3\b|WinError.?5\b"  # Win32 error codes
     r"|WinError.?32\b|WinError.?1060\b|WinError.?1067\b"
     r"|system.*restore.*fail|gpupdate.*fail"
     r"|Windows.Resource.Protection.*corrupt"        # sfc /scannow
     r"|sfc.*corrupt|component.store.*corrupt"
     r"|CBS\.log|DISM.*restorehealth"
     r"|UnauthorizedAccessException|Win32Exception"),

    # ── Service ───────────────────────────────────────────────────────────────
    (IncidentCategory.SERVICE,
     r"service.*crash|service.*hung|service.*stop|deadlock|restart.loop"
     r"|spooler|task.scheduler|daemon"
     r"|EventID.?7034\b|EventID.?7031\b|EventID.?7023\b" # crash/exit/error
     r"|EventID.?7036\b|EventID.?7040\b"             # state change
     r"|EventID.?7000\b|EventID.?7001\b|EventID.?7003\b" # start/dep fail
     r"|EventID.?7009\b|EventID.?7011\b|EventID.?7038\b" # timeout/hang/logon
     r"|EventID.?7024\b|EventID.?7029\b|EventID.?7035\b"
     r"|sc.*error|net.*start.*fail|service.*not.*respond"
     r"|The service.*did not start|Windows could not start"
     r"|service.*terminated.*unexpect|service.*exit.*code"
     r"|hung.state|StartPending|StopPending"
     r"|0x80070424|0x8007042c|0x8007041d|0x8007041c"  # service HRESULTs
     r"|HRESULT|pywintypes.*error|com_error"          # COM/pywin32 failures
     r"|WMI.*corrupt|winmgmt.*fail|wbem.*error"       # WMI failures
     r"|ServiceProcess.*TimeoutException"
     r"|spoolsv.*terminat"),

    # ── Dependency ────────────────────────────────────────────────────────────
    (IncidentCategory.DEPENDENCY,
     r"api.*down|upstream.*fail|503|dependency.*fail|sla.breach"
     r"|third.party|endpoint.*unreachable|circuit.break"
     r"|dll.*not.*found|module.*not.*found|assembly.*not.*found"
     r"|0x8007007E|0x80070126"                        # DLL not found
     r"|missing.*dll|failed.*load.*dll"),

    # ── Resource ──────────────────────────────────────────────────────────────
    (IncidentCategory.RESOURCE,
     r"oom|out.of.memory|memory.depletion|disk.full|disk.usage"
     r"|cpu.overload|quota.exceeded|swap|resource.exhaust"
     r"|EventID.?2004\b|EventID.?2013\b|EventID.?2019\b|EventID.?2020\b"
     r"|0xC0000017|0xC000012D"                        # no paging space
     r"|pagefile.*exhaust|commit.*limit|virtual.memory.*low"
     r"|disk.*space.*critical|No space left|ENOSPC|0x80070070"
     r"|CPU.*100|CPU.*sustain.*9[0-9]|WorkingSet.*grow"
     r"|high.*memory.*pressure|memory.*leak"
     r"|handle.*leak|handle.*count.*exceed"
     r"|NonPagedPool.*deplet|PagedPool.*deplet"),

    # ── Transient ─────────────────────────────────────────────────────────────
    (IncidentCategory.TRANSIENT,
     r"timeout|temporary|retry|flap|blip|transient|intermittent"
     r"|RPC.*timeout|WMI.*timeout|COM.*timeout"
     r"|operation.*timed.out|request.*timed.out|socket.*timeout"),

    # ── Systemic ──────────────────────────────────────────────────────────────
    (IncidentCategory.SYSTEMIC,
     r"systemic|cascad|widespread|multi.*service|global.*outage"
     r"|total.*failure|critical.*outage|full.degradation"),

    # ── Semantic ──────────────────────────────────────────────────────────────
    (IncidentCategory.SEMANTIC,
     r"assertion|logic.error|invariant|model.diverg|checksum.fail"
     r"|corrupt.state|data.integrity|referential.integrity"
     r"|EventID.?1002\b|EXCEPTION_ACCESS_VIOLATION"
     r"|EXCEPTION_STACK_OVERFLOW"),
]


class IncidentClassifier:
    def __init__(self):
        self._compiled = [
            (cat, re.compile(pat, re.IGNORECASE | re.VERBOSE))
            for cat, pat in _RULES
        ]

    def classify(self, event: Event) -> IncidentCategory:
        text = " ".join(filter(None, [
            event.error_type,
            event.message,
            event.subsystem,
            getattr(event, "raw", ""),
        ]))
        for cat, rx in self._compiled:
            if rx.search(text):
                return cat
        return IncidentCategory.UNKNOWN
