"""Windows Job Object containment for child processes.

Small ctypes wrapper over the kernel32 Job Object API verified by this
pack's probe: create a job with kill-on-close (+ optional process/memory
limits), assign a spawned child, expose a terminate. Non-Windows or
API-less hosts report ``job_object_ok: False`` and the ``basic`` tier is
unavailable; nothing here ever raises at import time.
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes

__all__ = [
    "JOBOBJECT_EXTENDED_LIMIT_INFORMATION",
    "JOB_LIMIT_FLAGS",
    "assign_process_to_job",
    "close_job",
    "create_contained_job",
    "job_object_available",
    "job_processes",
    "terminate_job",
]

logger = logging.getLogger(__name__)

JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000001
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000

JOBOBJECT_EXTENDED_LIMIT = 0x9
_JOB_NONE = 0

_JOB_OBJECTS_STILL_ACTIVE = 0x00000009
JobObjectBasicProcessIdList = 0x3


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    """win32 JOBOBJECT_BASIC_LIMIT_INFORMATION."""

    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    """win32 IO_COUNTERS."""

    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    """win32 JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""

    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _kernel32() -> ctypes.WinDLL | None:
    try:
        return ctypes.windll.kernel32
    except (AttributeError, OSError):
        return None


def job_object_available() -> bool:
    """True when CreateJobObjectW is callable (Windows)."""
    k32 = _kernel32()
    if k32 is None:
        return False
    try:
        handle = k32.CreateJobObjectW(None, None)
        if not handle:
            return False
        k32.CloseHandle(handle)
    except Exception:
        return False
    return True


_JOB_LIMIT_FLAGS = {
    "process": JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    "memory": JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    "kill_on_close": JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    "no_breakaway": JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
}

#: Public alias: {axis: flag} for callers composing a limit set.
JOB_LIMIT_FLAGS = dict(_JOB_LIMIT_FLAGS)


def create_contained_job(
    *,
    max_processes: int = 0,
    memory_mb: int = 0,
    kill_on_close: bool = True,
    no_breakaway: bool = True,
) -> int:
    """Create a job object; return its handle (0 on failure).

    ``max_processes``/``memory_mb`` of 0 mean "no cap on that axis".
    """
    k32 = _kernel32()
    if k32 is None:
        return _JOB_NONE
    handle = k32.CreateJobObjectW(None, None)
    if not handle:
        return _JOB_NONE
    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    flags = 0
    if kill_on_close:
        flags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if no_breakaway:
        flags |= _JOB_LIMIT_FLAGS["no_breakaway"]
    if max_processes > 0:
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = int(max_processes)
    if memory_mb > 0:
        flags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
        info.ProcessMemoryLimit = int(memory_mb) * 1024 * 1024
    info.BasicLimitInformation.LimitFlags = flags
    ok = k32.SetInformationJobObject(
        handle,
        JOBOBJECT_EXTENDED_LIMIT,
        ctypes.byref(info),
        ctypes.sizeof(info),
    )
    if not ok:
        logger.debug("pwsh: SetInformationJobObject failed (err=%s)", k32.GetLastError())
        k32.CloseHandle(handle)
        return _JOB_NONE
    return int(handle)


def assign_process_to_job(job_handle: int, process_pid: int) -> bool:
    """Assign a spawned child to the containment job. Best-effort by design."""
    k32 = _kernel32()
    if k32 is None or not job_handle or not process_pid:
        return False
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001
    h = k32.OpenProcess(
        PROCESS_SET_QUOTA | PROCESS_TERMINATE,
        False,
        int(process_pid),
    )
    if not h:
        logger.debug("pwsh: OpenProcess for job assign failed (err=%s)", k32.GetLastError())
        return False
    try:
        ok = bool(k32.AssignProcessToJobObject(wintypes.HANDLE(job_handle), wintypes.HANDLE(h)))
        if not ok:
            logger.debug("pwsh: AssignProcessToJobObject failed (err=%s)", k32.GetLastError())
        return ok
    finally:
        k32.CloseHandle(h)


def terminate_job(job_handle: int, exit_code: int = 1) -> bool:
    """Kill every process in the job (child tree containment)."""
    k32 = _kernel32()
    if k32 is None or not job_handle:
        return False
    return bool(k32.TerminateJobObject(wintypes.HANDLE(job_handle), int(exit_code)))


def close_job(job_handle: int) -> None:
    """Release the job handle; KILL_ON_JOB_CLOSE kills orphans."""
    k32 = _kernel32()
    if k32 is None or not job_handle:
        return
    k32.CloseHandle(wintypes.HANDLE(job_handle))


def job_processes(job_handle: int) -> list[int]:
    """Return PIDs currently in the job (diagnostics/tests).

    JOBOBJECT_BASIC_PROCESS_ID_LIST layout: two leading DWORDs
    (NumberOfAssignedProcesses, NumberOfProcessIdsInList) then the PIDs.
    """
    k32 = _kernel32()
    if k32 is None or not job_handle:
        return []
    buf = (wintypes.DWORD * 132)()
    written = wintypes.DWORD()
    ok = k32.QueryInformationJobObject(
        job_handle,
        JobObjectBasicProcessIdList,
        ctypes.byref(buf),
        ctypes.sizeof(buf),
        ctypes.byref(written),
    )
    if not ok or not written.value:
        return []
    count = int(buf[1])
    if count <= 0:
        return []
    return [int(buf[2 + i]) for i in range(count) if int(buf[2 + i]) > 0]
