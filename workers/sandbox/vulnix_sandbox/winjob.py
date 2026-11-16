"""Job Objects de Windows: límites de memoria y procesos, y muerte garantizada del árbol de procesos.

El proceso se crea SUSPENDIDO, se asigna al Job y solo entonces se reanuda (sin ventana de carrera
en la que pudiera lanzar hijos fuera del Job).
"""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes as wt

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000

_JobObjectExtendedLimitInformation = 9
_LIMIT_ACTIVE_PROCESS = 0x00000008
_LIMIT_PROCESS_MEMORY = 0x00000100
_LIMIT_JOB_MEMORY = 0x00000200
_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _BASIC_LIMIT(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wt.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wt.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wt.DWORD), ("SchedulingClass", wt.DWORD),
    ]


class _EXTENDED_LIMIT(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BASIC_LIMIT), ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ntdll = ctypes.WinDLL("ntdll")
_k32.CreateJobObjectW.restype = wt.HANDLE
_k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wt.LPCWSTR]
_k32.SetInformationJobObject.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
_k32.SetInformationJobObject.restype = wt.BOOL
_k32.AssignProcessToJobObject.argtypes = [wt.HANDLE, wt.HANDLE]
_k32.AssignProcessToJobObject.restype = wt.BOOL
_k32.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]
_k32.CloseHandle.argtypes = [wt.HANDLE]
_ntdll.NtResumeProcess.argtypes = [wt.HANDLE]


class JobObject:
    def __init__(self, process_memory_mb: int, job_memory_mb: int, max_processes: int):
        self.handle = _k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW falló")
        info = _EXTENDED_LIMIT()
        info.BasicLimitInformation.LimitFlags = (
            _LIMIT_KILL_ON_JOB_CLOSE | _LIMIT_DIE_ON_UNHANDLED_EXCEPTION | _LIMIT_ACTIVE_PROCESS
            | _LIMIT_PROCESS_MEMORY | _LIMIT_JOB_MEMORY)
        info.BasicLimitInformation.ActiveProcessLimit = max_processes
        info.ProcessMemoryLimit = process_memory_mb * 1024 * 1024
        info.JobMemoryLimit = job_memory_mb * 1024 * 1024
        if not _k32.SetInformationJobObject(self.handle, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(err, "SetInformationJobObject falló")

    def spawn(self, argv: list[str], **popen_kwargs) -> subprocess.Popen:
        flags = popen_kwargs.pop("creationflags", 0) | CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
        proc = subprocess.Popen(argv, creationflags=flags, **popen_kwargs)
        handle = wt.HANDLE(int(proc._handle))  # noqa: SLF001 - handle nativo del proceso
        if not _k32.AssignProcessToJobObject(self.handle, handle):
            err = ctypes.get_last_error()
            proc.kill()
            raise OSError(err, "AssignProcessToJobObject falló")
        if _ntdll.NtResumeProcess(handle) != 0:
            proc.kill()
            raise OSError("NtResumeProcess falló")
        return proc

    def terminate(self) -> None:
        if self.handle:
            _k32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if self.handle:
            _k32.CloseHandle(self.handle)  # KILL_ON_JOB_CLOSE mata cualquier proceso restante
            self.handle = None
