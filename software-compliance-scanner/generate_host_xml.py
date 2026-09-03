import argparse
import getpass
import os
import xml.etree.ElementTree as ET
from xml.dom import minidom

from remote_registry import (
    authenticate,
    disconnect,
    query_values
)

from os_detection import detect_remote_os


UNINSTALL_KEYS = [
    (
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "64-bit"
    ),
    (
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "32-bit"
    )
]


MSI_KEYS = [
    (
        r"HKLM\SOFTWARE\Classes\Installer\Products",
        "64-bit"
    ),
    (
        r"HKLM\SOFTWARE\WOW6432Node\Classes\Installer\Products",
        "32-bit"
    )
]


def print_header(title):

    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def get_value(values, name):

    item = values.get(name)

    if not item:
        return None

    return item.get("value")


def collect_uninstall(host):

    results = []

    for registry_key, architecture in UNINSTALL_KEYS:

        success, values, raw = query_values(
            host,
            registry_key
        )

        if not success:
            continue

        # reg query /s produces multiple subkeys.
        # We use a direct reg query with /s below.
        #
        # This function is replaced by collect_uninstall_recursive().
        #
        # Keeping this function simple for now.

    return results


def query_recursive(host, registry_path):

    """
    Query registry recursively.
    """

    from remote_registry import reg_query

    remote_path = rf"\\{host}\{registry_path}"

    import subprocess

    result = subprocess.run(
        [
            "reg",
            "query",
            remote_path,
            "/s"
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return False, result.stdout + result.stderr

    return True, result.stdout


def parse_recursive_registry(output):

    """
    Parse output from:

        reg query ... /s

    into:

        [
            {
                "key": "...",
                "values": {
                    "DisplayName": "...",
                    "DisplayVersion": "..."
                }
            }
        ]
    """

    entries = []

    current_key = None
    current_values = {}

    for line in output.splitlines():

        line = line.rstrip()

        if not line.strip():
            continue

        # Registry key
        if line.startswith("HKEY_"):

            if current_key is not None:

                entries.append({
                    "key": current_key,
                    "values": current_values
                })

            current_key = line.strip()
            current_values = {}

            continue

        parts = line.strip().split(None, 2)

        if len(parts) == 3:

            name = parts[0]
            reg_type = parts[1]
            value = parts[2]

            current_values[name] = {
                "type": reg_type,
                "value": value
            }

    if current_key is not None:

        entries.append({
            "key": current_key,
            "values": current_values
        })

    return entries


def collect_software(host):

    software = []

    for registry_key, architecture in UNINSTALL_KEYS:

        success, output = query_recursive(
            host,
            registry_key
        )

        if not success:
            continue

        entries = parse_recursive_registry(output)

        for entry in entries:

            values = entry["values"]

            display_name = get_value(
                values,
                "DisplayName"
            )

            if not display_name:
                continue

            software.append({
                "registry_key": entry["key"],
                "architecture": architecture,
                "display_name": display_name,
                "display_version": get_value(
                    values,
                    "DisplayVersion"
                ),
                "major_version": get_value(
                    values,
                    "MajorVersion"
                ),
                "minor_version": get_value(
                    values,
                    "MinorVersion"
                ),
                "publisher": get_value(
                    values,
                    "Publisher"
                ),
                "install_location": get_value(
                    values,
                    "InstallLocation"
                ),
                "uninstall_string": get_value(
                    values,
                    "UninstallString"
                ),
                "quiet_uninstall_string": get_value(
                    values,
                    "QuietUninstallString"
                )
            })

    return software


def collect_msi(host):

    products = []

    for registry_key, architecture in MSI_KEYS:

        success, output = query_recursive(
            host,
            registry_key
        )

        if not success:
            continue

        entries = parse_recursive_registry(output)

        for entry in entries:

            values = entry["values"]

            product_name = (
                get_value(values, "ProductName")
                or get_value(values, "DisplayName")
            )

            product_version = (
                get_value(values, "ProductVersion")
            )

            if not product_name and not product_version:
                continue

            products.append({
                "registry_key": entry["key"],
                "architecture": architecture,
                "product_name": product_name,
                "product_version": product_version,
                "display_name": get_value(
                    values,
                    "DisplayName"
                )
            })

    return products


def add_text(parent, tag, value):

    element = ET.SubElement(parent, tag)

    if value is not None:
        element.text = str(value)

    return element


def build_xml(host, os_info, software, msi):

    root = ET.Element(
        "host_info",
        {
            "version": "1.0"
        }
    )

    host_element = ET.SubElement(
        root,
        "host"
    )

    add_text(
        host_element,
        "ip",
        host
    )

    # ------------------------------------------------
    # OS
    # ------------------------------------------------

    os_element = ET.SubElement(
        host_element,
        "operating_system"
    )

    add_text(
        os_element,
        "product_name",
        os_info.get("product_name")
    )

    add_text(
        os_element,
        "display_version",
        os_info.get("display_version")
    )

    add_text(
        os_element,
        "current_build",
        os_info.get("current_build")
    )

    add_text(
        os_element,
        "ubr",
        os_info.get("ubr")
    )

    add_text(
        os_element,
        "full_build",
        os_info.get("full_build")
    )

    add_text(
        os_element,
        "architecture",
        os_info.get("architecture")
    )

    add_text(
        os_element,
        "installation_type",
        os_info.get("installation_type")
    )

    add_text(
        os_element,
        "edition_id",
        os_info.get("edition_id")
    )

    add_text(
        os_element,
        "build_branch",
        os_info.get("build_branch")
    )

    add_text(
        os_element,
        "build_lab",
        os_info.get("build_lab")
    )

    # ------------------------------------------------
    # Software
    # ------------------------------------------------

    software_element = ET.SubElement(
        host_element,
        "software"
    )

    for item in software:

        sw = ET.SubElement(
            software_element,
            "application"
        )

        add_text(
            sw,
            "display_name",
            item["display_name"]
        )

        add_text(
            sw,
            "display_version",
            item["display_version"]
        )

        add_text(
            sw,
            "major_version",
            item["major_version"]
        )

        add_text(
            sw,
            "minor_version",
            item["minor_version"]
        )

        add_text(
            sw,
            "publisher",
            item["publisher"]
        )

        add_text(
            sw,
            "architecture",
            item["architecture"]
        )

        add_text(
            sw,
            "install_location",
            item["install_location"]
        )

        add_text(
            sw,
            "uninstall_string",
            item["uninstall_string"]
        )

        add_text(
            sw,
            "quiet_uninstall_string",
            item["quiet_uninstall_string"]
        )

        add_text(
            sw,
            "registry_key",
            item["registry_key"]
        )

    # ------------------------------------------------
    # MSI
    # ------------------------------------------------

    msi_element = ET.SubElement(
        host_element,
        "msi_products"
    )

    for item in msi:

        product = ET.SubElement(
            msi_element,
            "product"
        )

        add_text(
            product,
            "product_name",
            item["product_name"]
        )

        add_text(
            product,
            "product_version",
            item["product_version"]
        )

        add_text(
            product,
            "display_name",
            item["display_name"]
        )

        add_text(
            product,
            "architecture",
            item["architecture"]
        )

        add_text(
            product,
            "registry_key",
            item["registry_key"]
        )

    return root


def save_xml(root, filename):

    rough_string = ET.tostring(
        root,
        encoding="utf-8"
    )

    reparsed = minidom.parseString(
        rough_string
    )

    pretty_xml = reparsed.toprettyxml(
        indent="    ",
        encoding="UTF-8"
    )

    with open(filename, "wb") as f:
        f.write(pretty_xml)


def main():

    parser = argparse.ArgumentParser(
        description="Windows Remote Registry Host Discovery"
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP / hostname"
    )

    parser.add_argument(
        "-u",
        "--username",
        required=True,
        help="Username"
    )

    parser.add_argument(
        "-p",
        "--password",
        help="Password"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output XML file"
    )

    args = parser.parse_args()

    password = args.password

    if password is None:

        password = getpass.getpass(
            "Password: "
        )

    print_header(
        "WINDOWS HOST DISCOVERY"
    )

    print(
        f"Target   : {args.target}"
    )

    print(
        f"Username : {args.username}"
    )

    print()

    # ------------------------------------------------
    # Authentication
    # ------------------------------------------------

    print(
        "[*] Authenticating through IPC$..."
    )

    authenticated, message = authenticate(
        args.target,
        args.username,
        password
    )

    if not authenticated:

        print(
            "[!] Authentication failed"
        )

        print(message)

        return 1

    print(
        "[+] Authentication successful"
    )

    try:

        # ------------------------------------------------
        # OS
        # ------------------------------------------------

        print(
            "[*] Detecting operating system..."
        )

        os_info = detect_remote_os(
            args.target
        )

        print()

        print_header(
            "OPERATING SYSTEM"
        )

        print(
            f"Product Name    : "
            f"{os_info.get('product_name')}"
        )

        print(
            f"Display Version : "
            f"{os_info.get('display_version')}"
        )

        print(
            f"Build           : "
            f"{os_info.get('full_build')}"
        )

        print(
            f"Architecture    : "
            f"{os_info.get('architecture')}"
        )

        print(
            f"Installation    : "
            f"{os_info.get('installation_type')}"
        )

        # ------------------------------------------------
        # Software
        # ------------------------------------------------

        print()

        print(
            "[*] Collecting installed software..."
        )

        software = collect_software(
            args.target
        )

        print(
            f"[+] Software entries : {len(software)}"
        )

        # ------------------------------------------------
        # MSI
        # ------------------------------------------------

        print(
            "[*] Collecting MSI evidence..."
        )

        msi = collect_msi(
            args.target
        )

        print(
            f"[+] MSI entries      : {len(msi)}"
        )

        # ------------------------------------------------
        # XML
        # ------------------------------------------------

        root = build_xml(
            args.target,
            os_info,
            software,
            msi
        )

        output = args.output

        if not output:

            os.makedirs(
                "hosts",
                exist_ok=True
            )

            output = os.path.join(
                "hosts",
                f"{args.target}.xml"
            )

        save_xml(
            root,
            output
        )

        print()

        print_header(
            "DISCOVERY COMPLETE"
        )

        print(
            f"Host XML : {output}"
        )

    finally:

        disconnect(
            args.target
        )

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )