from remote_registry import query_values


CURRENT_VERSION_KEY = (
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
)

ENVIRONMENT_KEY = (
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
)


def get_value(values, name, default=None):

    item = values.get(name)

    if not item:
        return default

    return item.get("value", default)


def parse_int(value):

    if value is None:
        return None

    try:
        value = str(value).strip()

        if value.lower().startswith("0x"):
            return int(value, 16)

        return int(value)

    except (ValueError, TypeError):
        return None


def detect_architecture(host):

    success, values, _ = query_values(
        host,
        ENVIRONMENT_KEY
    )

    if not success:
        return "Unknown"

    processor_arch = get_value(
        values,
        "PROCESSOR_ARCHITECTURE"
    )

    arch_w6432 = get_value(
        values,
        "PROCESSOR_ARCHITEW6432"
    )

    # 32-bit process on 64-bit OS
    if arch_w6432:
        if "AMD64" in arch_w6432.upper():
            return "64-bit"

        if "ARM64" in arch_w6432.upper():
            return "ARM64"

    if processor_arch:

        arch = processor_arch.upper()

        if arch == "AMD64":
            return "64-bit"

        if arch == "ARM64":
            return "ARM64"

        if arch == "x86":
            return "32-bit"

    return "Unknown"


def detect_remote_os(host):

    success, values, raw = query_values(
        host,
        CURRENT_VERSION_KEY
    )

    if not success:
        return {
            "detected": False,
            "error": raw,
            "product_name": None,
            "display_version": None,
            "current_build": None,
            "ubr": None,
            "full_build": None,
            "architecture": "Unknown",
            "installation_type": None
        }

    product_name = get_value(
        values,
        "ProductName"
    )

    display_version = get_value(
        values,
        "DisplayVersion"
    )

    # Older Windows versions
    if not display_version:
        display_version = get_value(
            values,
            "ReleaseId"
        )

    current_build = get_value(
        values,
        "CurrentBuild"
    )

    if not current_build:
        current_build = get_value(
            values,
            "CurrentBuildNumber"
        )

    ubr_raw = get_value(
        values,
        "UBR"
    )

    ubr = parse_int(ubr_raw)

    # Construct complete build
    full_build = current_build

    if current_build and ubr is not None:
        full_build = f"{current_build}.{ubr}"

    architecture = detect_architecture(host)

    installation_type = get_value(
        values,
        "InstallationType"
    )

    edition_id = get_value(
        values,
        "EditionID"
    )

    build_branch = get_value(
        values,
        "BuildBranch"
    )

    build_lab = get_value(
        values,
        "BuildLabEx"
    )

    return {
        "detected": True,
        "product_name": product_name,
        "display_version": display_version,
        "current_build": current_build,
        "ubr": ubr,
        "full_build": full_build,
        "architecture": architecture,
        "installation_type": installation_type,
        "edition_id": edition_id,
        "build_branch": build_branch,
        "build_lab": build_lab
    }