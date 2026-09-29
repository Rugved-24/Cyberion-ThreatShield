"""Inventory the host environment for the engagement record.

Written before anything else in the engagement so that the environment later
claimed in the report is observed rather than assumed. Output is JSON so the
final status report can derive its environment section from this file instead of
from prose.

    python scripts/environment_inventory.py
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command, timeout=90):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                shell=False)
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"{type(error).__name__}: {error}"
    output = (result.stdout or result.stderr or "").strip()
    return (output if result.returncode == 0 else None), (None if result.returncode == 0 else output)


def registry_value(hive, key, name):
    try:
        import winreg
    except ModuleNotFoundError:
        return None
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    try:
        with winreg.OpenKey(hives[hive], key) as handle:
            value, _ = winreg.QueryValueEx(handle, name)
            return value
    except OSError:
        return None


def memory_bytes():
    try:
        import ctypes

        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        return {"total_bytes": status.ullTotalPhys, "available_bytes": status.ullAvailPhys}
    except Exception:  # noqa: BLE001 - inventory must not fail on one probe
        return None


def storage(paths):
    volumes = []
    for drive in sorted({Path(p).anchor for p in paths if p}):
        try:
            usage = shutil.disk_usage(drive)
        except OSError:
            continue
        volumes.append({
            "volume": drive,
            "total_bytes": usage.total,
            "free_bytes": usage.free,
        })
    return volumes


def probe_executables(candidates, path_only=()):
    """Locate tools on PATH.

    Browsers and any GUI executable are checked for presence only. On Windows
    `msedge --version` and `chrome --version` do not reliably return, and
    invoking them can block the whole inventory, so they are never executed.
    """
    found = {}
    for label, command in candidates.items():
        path = shutil.which(command)
        if not path:
            continue
        if label in path_only:
            found[label] = {"path": path, "version": None, "note": "presence only, not invoked"}
            continue
        version, _ = run([path, "--version"], timeout=20)
        found[label] = {"path": path,
                        "version": (version or "").splitlines()[0] if version else None}
    return found


def virtualization():
    features = registry_value("HKLM", r"SYSTEM\CurrentControlSet\Control\HypervisorInformation",
                              "HypervisorPresent")
    vmms = registry_value("HKLM", r"SYSTEM\CurrentControlSet\Services", "VBoxService")
    result = {
        "hypervisor_present": bool(features) if features is not None else None,
        "hypervisor_feature_registry": features,
        "vmware_service_present": vmms is not None,
        "hyper_v_enabled": registry_value("HKLM", r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
                                         "VirtualMachineType") is not None,
        "platforms_on_path": sorted(name for name, command in {
            "VirtualBox": "VBoxManage", "VMware": "vmrun", "Hyper-V": "hvc"}.items()
            if shutil.which(command)),
        "system_manufacturer": registry_value("HKLM", r"HARDWARE\DESCRIPTION\System\BIOS",
                                              "SystemManufacturer"),
        "system_model": registry_value("HKLM", r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
    }
    return result


def office_software():
    return {
        "excel_installed": bool(registry_value("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\excel.exe", "")),
        "powerpoint_installed": bool(registry_value("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\POWERPNT.EXE", "")),
        "word_installed": bool(registry_value("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WINWORD.EXE", "")),
        "libreoffice_on_path": shutil.which("soffice"),
    }


def python_environment():
    import pandas
    import yaml
    info = {
        "interpreter": sys.executable,
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "in_virtualenv": sys.prefix != sys.base_prefix,
        "packages": {"pandas": pandas.__version__, "PyYAML": yaml.__version__},
    }
    for name, module in (("numpy", "numpy"), ("sigma", "sigma"), ("matplotlib", "matplotlib"),
                         ("openpyxl", "openpyxl"), ("jupyterlab", "jupyterlab"),
                         ("ipykernel", "ipykernel"), ("pytest", "pytest")):
        try:
            imported = __import__(module)
            info["packages"][name] = getattr(imported, "__version__", "present")
        except ModuleNotFoundError:
            info["packages"][name] = None
    try:
        output, _ = run([sys.executable, "-m", "ipykernel", "list"])
        info["jupyter_kernels"] = output.splitlines() if output else []
    except Exception:  # noqa: BLE001
        info["jupyter_kernels"] = []
    return info


def main():
    inventory = {
        "captured_utc": datetime.now(UTC).isoformat(),
        "host": {
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor() or registry_value(
                "HKLM", r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"),
            "cpu_logical_cores": os.cpu_count(),
            "memory": memory_bytes(),
            "hostname": platform.node(),
        },
        "storage": storage([str(ROOT), "C:\\", "D:\\", "E:\\"]),
        "python": python_environment(),
        "tools_on_path": probe_executables({
            "git": "git", "pwsh": "pwsh", "powershell": "powershell",
            "code": "code", "jupyter": "jupyter", "jupyter-lab": "jupyter-lab",
            "sigma": "sigma", "py": "py", "7z": "7z", "pandoc": "pandoc",
            "chrome": "chrome", "msedge": "msedge", "firefox": "firefox",
        }, path_only=("chrome", "msedge", "firefox")),
        "powershell_editions": {},
        "virtualization": virtualization(),
        "office": office_software(),
        "repository": {
            "path": str(ROOT),
            "git": bool(shutil.which("git")),
            "remotes": (run(["git", "remote", "-v"])[0] or "").splitlines(),
            "commits": int((run(["git", "rev-list", "--count", "HEAD"])[0] or "0").strip() or 0),
        },
    }
    for name, path in (("windows_powershell", "powershell"), ("powershell_7", "pwsh")):
        located = shutil.which(path)
        if located:
            output, _ = run([located, "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"])
            inventory["powershell_editions"][name] = {"path": located, "version": output}

    destination = ROOT / "docs" / "environment-inventory.json"
    destination.write_text(json.dumps(inventory, indent=2, default=str) + "\n",
                           encoding="utf-8", newline="\n")
    host = inventory["host"]
    print(f"OS            : {host['os']} {host['os_release']} ({host['architecture']})")
    print(f"CPU / RAM     : {host['cpu_logical_cores']} logical cores, "
          f"{(host['memory'] or {}).get('total_bytes', 0) // (1024 ** 3)} GiB")
    print(f"Python        : {inventory['python']['version']} in venv="
          f"{inventory['python']['in_virtualenv']}")
    print(f"Git           : commits={inventory['repository']['commits']} "
          f"remotes={len(inventory['repository']['remotes'])}")
    print(f"PowerShell    : {list(inventory['powershell_editions'])}")
    print(f"Virtualization: hypervisor={inventory['virtualization']['hypervisor_present']} "
          f"platforms={inventory['virtualization']['platforms_on_path']}")
    print(f"Office        : excel={inventory['office']['excel_installed']} "
          f"powerpoint={inventory['office']['powerpoint_installed']}")
    print(f"Jupyter kernels: {inventory['python']['jupyter_kernels']}")
    print(f"written: {destination.relative_to(ROOT).as_posix()}")


if __name__ == "__main__":
    main()
