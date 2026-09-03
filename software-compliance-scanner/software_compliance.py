import argparse
import xml.etree.ElementTree as ET


def print_header(title):

    print()
    print("=" * 80)
    print(title)
    print("=" * 80)


def normalize_version(version):

    if not version:
        return None

    version = str(version).strip()

    parts = []

    for part in version.split("."):

        digits = ""

        for char in part:

            if char.isdigit():
                digits += char
            else:
                break

        if digits:
            parts.append(
                int(digits)
            )
        else:
            parts.append(0)

    while len(parts) < 4:
        parts.append(0)

    return tuple(parts[:4])


def version_compare(installed, required):

    installed_v = normalize_version(
        installed
    )

    required_v = normalize_version(
        required
    )

    if not installed_v:
        return None

    if not required_v:
        return None

    if installed_v >= required_v:
        return True

    return False


def load_policy(filename):

    tree = ET.parse(filename)

    root = tree.getroot()

    policies = []

    for software in root.findall("software"):

        name = software.get("name")

        minimum_version = software.get(
            "minimum_version"
        )

        match_values = []

        match_element = software.find(
            "match"
        )

        if match_element is not None:

            for item in match_element.findall(
                "contains"
            ):

                if item.text:
                    match_values.append(
                        item.text.strip()
                    )

        policies.append({
            "name": name,
            "minimum_version": minimum_version,
            "match": match_values
        })

    return policies


def load_host(filename):

    tree = ET.parse(filename)

    root = tree.getroot()

    host = root.find("host")

    if host is None:
        raise RuntimeError(
            "Invalid host XML"
        )

    return host


def get_text(parent, name):

    element = parent.find(name)

    if element is None:
        return None

    return element.text


def find_matching_software(
    host,
    match_values
):

    results = []

    software_element = host.find(
        "software"
    )

    if software_element is None:
        return results

    applications = software_element.findall(
        "application"
    )

    for application in applications:

        display_name = get_text(
            application,
            "display_name"
        )

        if not display_name:
            continue

        name_lower = display_name.lower()

        for match in match_values:

            if match.lower() in name_lower:

                results.append(
                    application
                )

                break

    return results


def get_effective_version(application):

    versions = []

    display_version = get_text(
        application,
        "display_version"
    )

    major = get_text(
        application,
        "major_version"
    )

    minor = get_text(
        application,
        "minor_version"
    )

    if display_version:
        versions.append(
            display_version
        )

    if major and minor:

        versions.append(
            f"{major}.{minor}"
        )

    valid_versions = [
        v for v in versions
        if normalize_version(v)
    ]

    if not valid_versions:
        return None

    valid_versions.sort(
        key=normalize_version,
        reverse=True
    )

    return valid_versions[0]


def main():

    parser = argparse.ArgumentParser(
        description="Windows Software Compliance Analyzer"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="Host XML"
    )

    parser.add_argument(
        "-p",
        "--policy",
        required=True,
        help="Software policy XML"
    )

    args = parser.parse_args()

    host = load_host(
        args.input
    )

    policies = load_policy(
        args.policy
    )

    # ------------------------------------------------
    # Host information
    # ------------------------------------------------

    ip = get_text(
        host,
        "ip"
    )

    os_element = host.find(
        "operating_system"
    )

    print_header(
        "TARGET INFORMATION"
    )

    print(
        f"Target        : {ip}"
    )

    if os_element is not None:

        print(
            f"OS            : "
            f"{get_text(os_element, 'product_name')}"
        )

        print(
            f"Display       : "
            f"{get_text(os_element, 'display_version')}"
        )

        print(
            f"Build         : "
            f"{get_text(os_element, 'full_build')}"
        )

        print(
            f"Architecture  : "
            f"{get_text(os_element, 'architecture')}"
        )

    # ------------------------------------------------
    # Compliance
    # ------------------------------------------------

    print_header(
        "SOFTWARE COMPLIANCE"
    )

    not_compliant = 0

    for policy in policies:

        policy_name = policy["name"]

        required_version = policy[
            "minimum_version"
        ]

        matches = find_matching_software(
            host,
            policy["match"]
        )

        print()
        print(
            f"[ {policy_name} ]"
        )

        print(
            f"Required Version : "
            f"{required_version}"
        )

        if not matches:

            print(
                "Status           : NOT_INSTALLED"
            )

            continue

        best_version = None
        best_application = None

        for application in matches:

            version = get_effective_version(
                application
            )

            if not version:
                continue

            if (
                best_version is None
                or normalize_version(version)
                > normalize_version(best_version)
            ):

                best_version = version
                best_application = application

        if not best_version:

            print(
                "Status           : "
                "VERSION_UNKNOWN"
            )

            continue

        compliant = version_compare(
            best_version,
            required_version
        )

        if compliant:

            status = "COMPLY"

        else:

            status = "NOT_COMPLY"
            not_compliant += 1

        print(
            f"Installed Version: "
            f"{best_version}"
        )

        print(
            f"Status           : "
            f"{status}"
        )

        if best_application is not None:

            print(
                f"Registry Key     : "
                f"{get_text(best_application, 'registry_key')}"
            )

            print(
                f"Architecture     : "
                f"{get_text(best_application, 'architecture')}"
            )

    print()

    print_header(
        "SUMMARY"
    )

    if not_compliant == 0:

        print(
            "Overall Status : COMPLY"
        )

    else:

        print(
            "Overall Status : NOT_COMPLY"
        )

        print(
            f"Failed Policies: {not_compliant}"
        )

    return (
        2
        if not_compliant
        else 0
    )


if __name__ == "__main__":

    raise SystemExit(
        main()
    )