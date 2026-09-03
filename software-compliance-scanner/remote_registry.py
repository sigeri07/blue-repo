import subprocess
import re


def authenticate(host, username, password):
    """
    Authenticate to target through IPC$.
    """

    cmd = [
        "net",
        "use",
        rf"\\{host}\IPC$",
        password,
        f"/user:{username}",
        "/persistent:no"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False
    )

    if result.returncode != 0:
        return False, result.stdout + result.stderr

    return True, result.stdout


def disconnect(host):
    """
    Remove SMB session.
    """

    subprocess.run(
        ["net", "use", rf"\\{host}\IPC$", "/delete", "/y"],
        capture_output=True,
        text=True
    )


def reg_query(host, registry_path):
    """
    Query remote registry using reg.exe.

    Example:
        HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion
    """

    remote_path = rf"\\{host}\{registry_path}"

    cmd = [
        "reg",
        "query",
        remote_path
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=False
    )

    output = result.stdout + result.stderr

    if result.returncode != 0:
        return False, output

    return True, result.stdout


def parse_reg_query(output):
    """
    Convert reg.exe output into dictionary.

    Example:
        DisplayVersion    REG_SZ    21H2

    becomes:

        {
            "DisplayVersion": "21H2"
        }
    """

    values = {}

    for line in output.splitlines():

        line = line.rstrip()

        if not line:
            continue

        # Skip registry key header
        if line.startswith("HKEY_"):
            continue

        # REG_SZ / REG_DWORD / etc
        match = re.match(
            r"^\s*(\S+)\s+(REG_\w+)\s+(.*)$",
            line
        )

        if not match:
            continue

        name = match.group(1)
        reg_type = match.group(2)
        value = match.group(3).strip()

        values[name] = {
            "type": reg_type,
            "value": value
        }

    return values


def query_values(host, registry_path):
    """
    Query registry and directly return parsed values.
    """

    success, output = reg_query(host, registry_path)

    if not success:
        return False, {}, output

    values = parse_reg_query(output)

    return True, values, output