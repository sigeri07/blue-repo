import argparse
import base64
import csv
import html
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NOT_JOINED_TEXT = "this computer is not joined to a domain"
TIMESTAMP_RE = re.compile(r"/Date\((-?\d+)(?:[+-]\d{4})?\)/")
INT_RE = re.compile(r"^-?\d+$")


# Function to convert Windows timestamp format to human-readable date (UTC)
def parse_windows_timestamp(timestamp):
    if not timestamp or not isinstance(timestamp, str):
        return "N/A"
    match = TIMESTAMP_RE.search(timestamp)
    if match:
        milliseconds = int(match.group(1))
        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    return timestamp  # already a readable value (e.g. an ISO date string)


def decode_base64(encoded_str):
    if not encoded_str or not encoded_str.strip():
        return "[]"
    return base64.b64decode(encoded_str.strip()).decode('utf-8-sig')


def load_json_section(root, tag):
    """Decode a Base64/JSON section of dump.xml into a list of dicts (empty list if missing or invalid)."""
    element = root.find(f".//{tag}")
    if element is None:
        return []
    try:
        data = json.loads(decode_base64(element.text))
    except (ValueError, TypeError):
        print(f"Warning: section <{tag}> could not be decoded, it will be empty in the report.")
        return []
    if data is None:
        return []
    if isinstance(data, dict):  # a single item serialised as an object
        return [data]
    return data


def safe_int(value):
    if value is None:
        return None
    if isinstance(value, str) and INT_RE.match(value.strip()):
        return int(value.strip())
    return value  # keep the original value (e.g., "Enabled", "Disabled")


def get_actual_result_from_dump(root, control_id):
    mbss_tag = control_id.replace('-', '')  # Remove hyphen to match tags like <MBSS001>

    mbss_element = root.find(f".//MBSS/{mbss_tag}")

    if mbss_element is not None and mbss_element.text and mbss_element.text.strip():
        return safe_int(mbss_element.text.strip())  # Convert to integer or return the original value
    return None  # Return None if not found


def parse_comparison_operator(expected_result):
    if isinstance(expected_result, str) and (expected_result.startswith(">=") or expected_result.startswith("<=")):
        operator = expected_result[:2]  # >= or <=
        value = safe_int(expected_result[2:].strip())  # Value after the operator
    else:
        operator = "=="
        value = safe_int(expected_result)  # If no operator, treat as exact comparison

    return operator, value


def _normalize(text):
    return " ".join(text.split()).casefold()


def _normalized_list(text):
    # Comma separated values, order and case insensitive, empty items (stray commas) ignored
    return sorted(_normalize(item) for item in text.split(",") if item.strip())


def check_compliance(actual_result, expected_result):
    # Handle case where both are None
    if actual_result is None and expected_result is None:
        return "Pass"  # Both results are missing, return "Pass"

    # If only one side is missing the control cannot be satisfied
    if actual_result is None or expected_result is None:
        return "Fail"

    operator, expected_value = parse_comparison_operator(expected_result)

    # Case when both expected_value and actual_result are integers
    if isinstance(expected_value, int) and isinstance(actual_result, int):
        if operator == ">=":
            return "Pass" if actual_result >= expected_value else "Fail"
        elif operator == "<=":
            return "Pass" if actual_result <= expected_value else "Fail"
        return "Pass" if actual_result == expected_value else "Fail"

    # Case when expected_value is string and actual_result is also string
    if isinstance(expected_value, str) and isinstance(actual_result, str) and operator == "==":
        if _normalize(actual_result) == _normalize(expected_value):
            return "Pass"

        expected_list = _normalized_list(expected_value)
        actual_list = _normalized_list(actual_result)

        # Pass if both lists match, or if actual_list equals expected_list with "IIS_IUSRS" removed
        # (IIS_IUSRS only exists when the Web Server role is installed).
        if actual_list == expected_list or actual_list == [item for item in expected_list if item != "iis_iusrs"]:
            return "Pass"

    # Mixed types (int vs string) cannot be compared; anything else is a mismatch
    return "Fail"


def child_text(element, tag):
    value = element.findtext(tag)
    return value.strip() if value else ""


def check_all_compliance(root, controls_root):
    compliance_results = []

    for control in controls_root.findall("control"):
        control_id = child_text(control, "id")
        domain = child_text(control, "domain")
        description = child_text(control, "description")
        mandatory = child_text(control, "mandatory")
        expected_result = child_text(control, "expected_result") or None

        result = {
            "control_id": control_id,
            "status": "Error",
            "domain": domain,
            "description": description,
            "mandatory": mandatory,
            "expected_result": expected_result,
            "actual_result": None,
            "failure_reason": "",
        }

        try:
            actual_result = get_actual_result_from_dump(root, control_id)
            status = check_compliance(actual_result, expected_result)
            result["actual_result"] = actual_result
            result["status"] = status
            if status == "Fail":
                if actual_result is None:
                    result["failure_reason"] = "No result found in the dump file"
                else:
                    result["failure_reason"] = "Expected and actual results do not match"
        except Exception as e:  # keep the report going; the control is shown with status "Error"
            result["failure_reason"] = str(e)

        compliance_results.append(result)

    return compliance_results


def read_system_info(root):
    info = {
        "timestamp": "unknown",
        "hostname": "unknown",
        "os": "unknown",
        "current_user": "",
        "ip_addresses": "",
        "domain_status": child_text(root, "DomainStatus"),
        "organizational_unit": child_text(root, "OrganizationalUnit"),
        "workgroup_name": child_text(root, "WorkgroupName"),
    }
    system_info = root.find(".//SystemInformation")
    if system_info is not None:
        info["timestamp"] = child_text(system_info, "Timestamp") or "unknown"
        info["hostname"] = child_text(system_info, "Hostname") or "unknown"
        info["os"] = child_text(system_info, "OS") or "unknown"
        info["current_user"] = child_text(system_info, "CurrentUser")
        info["ip_addresses"] = child_text(system_info, "IPAddresses")
    return info


def build_filename(info, extension):
    try:
        date_part = datetime.strptime(info["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d")
    except ValueError:
        date_part = datetime.now().strftime("%Y%m%d")
    name = f"{info['hostname']}-{info['os']}-{date_part}.{extension}"
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)  # characters not allowed in file names


def save_to_csv(results, root):
    info = read_system_info(root)
    filename = build_filename(info, "csv")

    if not results:
        print("No controls found, CSV was not written.")
        return

    keys = list(results[0].keys())
    # utf-8-sig so that Excel detects the encoding
    with open(filename, mode="w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

    print(f"Compliance results saved to {filename}.")


def esc(value):
    return html.escape("" if value is None else str(value))


def html_table(headers, rows):
    """rows: list of lists of already-escaped HTML cell strings (or (html, css_class) tuples)."""
    parts = ['<table border="1">', "<tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr>"]
    for row in rows:
        cells = []
        for cell in row:
            if isinstance(cell, tuple):
                cells.append(f'<td class="{cell[1]}">{cell[0]}</td>')
            else:
                cells.append(f"<td>{cell}</td>")
        parts.append("<tr>" + "".join(cells) + "</tr>")
    parts.append("</table>")
    return "\n".join(parts)


def scroll(value):
    return f"<div class='scrollable'>{esc(value)}</div>"


REPORT_CSS = """
:root {
    --ink: #1f2933;
    --muted: #5b6770;
    --navy: #1b3a5c;
    --rule: #c9d1d9;
    --band: #f3f5f7;
    --pass: #1e6b3a;
    --pass-bg: #e8f3ec;
    --fail: #a12622;
    --fail-bg: #fbeceb;
    --error: #8a5a00;
    --error-bg: #fbf3e0;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #e9ecef;
    color: var(--ink);
    font-family: "Segoe UI", Calibri, Arial, sans-serif;
    font-size: 13px;
    line-height: 1.5;
}
.page {
    max-width: 1100px;
    margin: 24px auto;
    padding: 56px 64px;
    background: #fff;
    border: 1px solid var(--rule);
}
h1, h2, h3 { font-family: Georgia, "Times New Roman", serif; color: var(--navy); font-weight: 600; }
h1 { font-size: 30px; margin: 0 0 4px; }
h2 { font-size: 20px; margin: 40px 0 12px; padding-bottom: 6px; border-bottom: 2px solid var(--navy); }
h3 { font-size: 15px; margin: 28px 0 8px; }
.cover { border-bottom: 4px solid var(--navy); padding-bottom: 24px; margin-bottom: 8px; }
.cover .subtitle { font-size: 16px; color: var(--muted); margin: 0 0 14px; }
.cover .classification { display: inline-block; border: 1px solid var(--fail); color: var(--fail); padding: 2px 10px; font-size: 12px; }
.meta { width: 100%; border-collapse: collapse; margin: 8px 0 0; }
.meta th { width: 190px; text-align: left; font-weight: 600; background: var(--band); }
.meta th, .meta td { border: 1px solid var(--rule); padding: 6px 10px; vertical-align: top; }
nav.toc { margin: 20px 0 0; padding: 12px 18px; background: var(--band); border-left: 4px solid var(--navy); }
nav.toc ol { margin: 6px 0 0; padding-left: 20px; }
nav.toc a { color: var(--navy); text-decoration: none; }
nav.toc a:hover, nav.toc a:focus { text-decoration: underline; }
.summary { display: flex; gap: 0; border: 1px solid var(--rule); margin: 12px 0 16px; }
.summary .cell { flex: 1; padding: 14px 16px; border-right: 1px solid var(--rule); }
.summary .cell:last-child { border-right: 0; }
.summary .num { display: block; font-family: Georgia, serif; font-size: 28px; line-height: 1.1; }
.summary .lbl { color: var(--muted); }
.bar { display: flex; height: 14px; border: 1px solid var(--rule); background: var(--band); }
.bar span { display: block; height: 100%; }
.bar .b-pass { background: var(--pass); }
.bar .b-fail { background: var(--fail); }
.bar .b-error { background: var(--error); }
.note { color: var(--muted); margin: 8px 0 0; }
table.data { width: 100%; border-collapse: collapse; margin: 8px 0 0; }
table.data th { background: var(--navy); color: #fff; text-align: left; font-weight: 600; }
table.data th, table.data td { border: 1px solid var(--rule); padding: 6px 8px; vertical-align: top; }
table.data tbody tr:nth-child(even) { background: #fafbfc; }
table.data td.num, table.data th.num { text-align: right; }
table.data.fixed { table-layout: fixed; }
table.data td:first-child { overflow-wrap: anywhere; }
table.data tr.row-fail td:first-child { border-left: 4px solid var(--fail); }
table.data tr.row-error td:first-child { border-left: 4px solid var(--error); }
table.data tr.row-pass td:first-child { border-left: 4px solid var(--pass); }
.badge { display: inline-block; min-width: 52px; text-align: center; padding: 1px 8px; border: 1px solid; font-weight: 600; }
.badge.pass { color: var(--pass); background: var(--pass-bg); border-color: var(--pass); }
.badge.fail { color: var(--fail); background: var(--fail-bg); border-color: var(--fail); }
.badge.error { color: var(--error); background: var(--error-bg); border-color: var(--error); }
.scrollable { max-height: 180px; overflow-y: auto; word-break: break-word; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 48px; padding-top: 10px; border-top: 1px solid var(--rule); color: var(--muted); font-size: 11px; }
@media (max-width: 760px) {
    .page { padding: 24px 16px; margin: 0; }
    .summary { flex-direction: column; }
    .summary .cell { border-right: 0; border-bottom: 1px solid var(--rule); }
    .meta th { width: 120px; }
    .wide { overflow-x: auto; }
}
@media print {
    body { background: #fff; font-size: 11px; }
    .page { margin: 0; padding: 0; border: 0; max-width: none; }
    h2 { break-after: avoid; }
    table.data thead { display: table-header-group; }
    table.data tr { break-inside: avoid; }
    .scrollable { max-height: none; overflow: visible; }
    nav.toc a { color: var(--ink); }
    * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    @page { size: A4 landscape; margin: 14mm; }
}
"""


def badge(status):
    css = "pass" if status == "Pass" else "fail" if status == "Fail" else "error"
    return f'<span class="badge {css}">{esc(status)}</span>'


def percent(part, whole):
    return f"{(part / whole * 100):.1f}%" if whole else "n/a"


def summarize(results):
    total = {"Pass": 0, "Fail": 0, "Error": 0}
    domains = {}
    for result in results:
        status = result["status"] if result["status"] in total else "Error"
        total[status] += 1
        entry = domains.setdefault(result["domain"] or "Uncategorized", {"Pass": 0, "Fail": 0, "Error": 0})
        entry[status] += 1
    return total, domains


def data_table(headers, rows, numeric_cols=(), empty_text="No data was collected for this section.", widths=None):
    if not rows:
        return f'<p class="empty">{esc(empty_text)}</p>'
    head = "".join(
        f'<th class="num">{esc(h)}</th>' if i in numeric_cols else f"<th>{esc(h)}</th>"
        for i, h in enumerate(headers))
    body = []
    for row in rows:
        row_class = ""
        if isinstance(row, tuple):
            row, row_class = row
        cells = "".join(
            f'<td class="num">{c}</td>' if i in numeric_cols else f"<td>{c}</td>"
            for i, c in enumerate(row))
        body.append(f'<tr class="{row_class}">{cells}</tr>')
    colgroup = ""
    table_class = "data"
    if widths:
        colgroup = "<colgroup>" + "".join(f'<col style="width:{w}">' for w in widths) + "</colgroup>"
        table_class = "data fixed"
    return (f'<div class="wide"><table class="{table_class}">{colgroup}<thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def save_to_html(results, root):
    info = read_system_info(root)
    filename = build_filename(info, "html")

    users = load_json_section(root, "User")
    processes = load_json_section(root, "Process")
    services = load_json_section(root, "Services")
    nets = load_json_section(root, "Netstat")
    installed = load_json_section(root, "InstalledSoftware")
    updates = load_json_section(root, "Updates")
    tasks = load_json_section(root, "TaskScheduler")

    total, domains = summarize(results)
    count = len(results)
    mandatory_fail = sum(1 for r in results if r["status"] == "Fail" and r["mandatory"].lower() == "mandatory")
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    # --- document information ---
    is_workgroup = info["domain_status"].strip().lower() == NOT_JOINED_TEXT
    meta_rows = [
        ("Hostname", info["hostname"]),
        ("Operating system", info["os"]),
        ("Assessment date", info["timestamp"]),
        ("Assessed by (account)", info["current_user"]),
        ("IP address(es)", info["ip_addresses"]),
        ("Domain", info["domain_status"]),
        ("Workgroup" if is_workgroup else "Organizational unit",
         info["workgroup_name"] if is_workgroup else info["organizational_unit"]),
        ("Report generated", generated),
    ]
    meta_html = "".join(f"<tr><th scope='row'>{esc(k)}</th><td>{esc(v) or '-'}</td></tr>" for k, v in meta_rows)

    # --- executive summary ---
    summary_html = f"""
    <div class="summary" role="group" aria-label="Assessment summary">
        <div class="cell"><span class="num">{count}</span><span class="lbl">Controls assessed</span></div>
        <div class="cell"><span class="num" style="color:var(--pass)">{total['Pass']}</span><span class="lbl">Compliant</span></div>
        <div class="cell"><span class="num" style="color:var(--fail)">{total['Fail']}</span><span class="lbl">Non-compliant</span></div>
        <div class="cell"><span class="num" style="color:var(--error)">{total['Error']}</span><span class="lbl">Not evaluated (error)</span></div>
        <div class="cell"><span class="num">{percent(total['Pass'], count)}</span><span class="lbl">Overall compliance</span></div>
    </div>
    <div class="bar" role="img" aria-label="Compliant {total['Pass']}, non-compliant {total['Fail']}, error {total['Error']}">
        <span class="b-pass" style="width:{(total['Pass'] / count * 100) if count else 0:.2f}%"></span>
        <span class="b-fail" style="width:{(total['Fail'] / count * 100) if count else 0:.2f}%"></span>
        <span class="b-error" style="width:{(total['Error'] / count * 100) if count else 0:.2f}%"></span>
    </div>
    <p class="note">{mandatory_fail} non-compliant control(s) are classified as Mandatory.
    </p>
    """

    domain_rows = []
    for name, c in domains.items():
        n = c["Pass"] + c["Fail"] + c["Error"]
        domain_rows.append([esc(name), str(n), str(c["Pass"]), str(c["Fail"]), str(c["Error"]), percent(c["Pass"], n)])
    domain_table = data_table(["Domain", "Controls", "Compliant", "Non-compliant", "Error", "Compliance"],
                              domain_rows, numeric_cols=(1, 2, 3, 4, 5))

    # --- detailed results, grouped by domain ---
    detail_html = []
    for name in domains:
        rows = []
        for r in results:
            if (r["domain"] or "Uncategorized") != name:
                continue
            css = "row-pass" if r["status"] == "Pass" else "row-fail" if r["status"] == "Fail" else "row-error"
            cells = [esc(r["control_id"]), esc(r["description"]), esc(r["mandatory"]),
                     scroll(r["expected_result"]), scroll(r["actual_result"]), badge(r["status"])]
            rows.append((cells, css))
        detail_html.append(f"<h3>{esc(name)}</h3>" + data_table(
            ["Control ID", "Control", "Priority", "Expected result", "Actual result", "Status"], rows,
            widths=["88px", "34%", "76px", "22%", "22%", "64px"]))

    # --- appendices ---
    appendix = [
        ("Local user accounts", data_table(
            ["User", "Groups", "Enabled", "Last logon (UTC)", "Password last set (UTC)"],
            [[esc(u.get("User")), esc(u.get("Groups")), esc(u.get("Status")),
              esc(parse_windows_timestamp(u.get("LastLogin"))),
              esc(parse_windows_timestamp(u.get("LastPasswordChange")))] for u in users])),
        ("Listening network ports", data_table(
            ["Local address", "Port", "PID", "Process"],
            [[esc(n.get("LocalAddress")), esc(n.get("LocalPort")), esc(n.get("PID")), esc(n.get("ProcessName"))]
             for n in nets], numeric_cols=(1, 2))),
        ("Services", data_table(
            ["Service name", "Display name", "PID", "State", "Start mode", "Run as"],
            [[esc(x.get("Name")), esc(x.get("DisplayName")), esc(x.get("PID")), esc(x.get("State")),
              esc(x.get("StartMode")), esc(x.get("RunAs"))] for x in services], numeric_cols=(2,))),
        ("Running processes", data_table(
            ["Process", "PID", "Path", "User"],
            [[esc(p.get("ProcessName")), esc(p.get("ProcessID")), scroll(p.get("Path")), esc(p.get("UserName"))]
             for p in processes], numeric_cols=(1,))),
        ("Installed software", data_table(
            ["Software", "Version", "Publisher", "Install date"],
            [[esc(i.get("DisplayName")), esc(i.get("DisplayVersion")), esc(i.get("Publisher")),
              esc(i.get("InstallDate"))] for i in installed])),
        ("Pending Windows updates", data_table(
            ["Update", "Update ID", "Reboot required", "KB article"],
            [[esc(u.get("Title")), esc(u.get("UpdateID")), esc(u.get("RebootRequired")), esc(u.get("KBArticleIDs"))]
             for u in updates], empty_text="No pending updates were found, or the update search could not be completed.")),
        ("Scheduled tasks", data_table(
            ["Task", "Path", "Run as", "Trigger enabled", "Last run", "Action"],
            [[esc(t.get("TaskName")), esc(t.get("TaskPath")), esc(t.get("User")), esc(t.get("ScheduleEnabled")),
              esc(t.get("LastRunTime")), scroll(t.get("BinaryPath"))] for t in tasks])),
    ]
    appendix_html = "".join(
        f'<h3 id="app-{i}">Appendix {chr(65 + i)}. {esc(title)}</h3>{body}' for i, (title, body) in enumerate(appendix))
    appendix_toc = "".join(
        f'<li><a href="#app-{i}">Appendix {chr(65 + i)}. {esc(title)}</a></li>' for i, (title, _) in enumerate(appendix))

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Assessment Report - {esc(info['hostname'])}</title>
    <style>{REPORT_CSS}</style>
</head>
<body>
<main class="page">
    <header class="cover">
        <h1>Security Configuration Assessment Report</h1>
        <p class="subtitle">{esc(info['os'])} - {esc(info['hostname'])}</p>
        <span class="classification">Confidential - internal use only</span>
    </header>

    <nav class="toc" aria-label="Contents">
        <strong>Contents</strong>
        <ol>
            <li><a href="#info">Document information</a></li>
            <li><a href="#summary">Executive summary</a></li>
            <li><a href="#results">Detailed results</a></li>
            <li><a href="#appendix">Appendices</a>
                <ol style="list-style:none;padding-left:16px">{appendix_toc}</ol></li>
        </ol>
    </nav>

    <h2 id="info">1. Document information</h2>
    <table class="meta"><tbody>{meta_html}</tbody></table>

    <h2 id="summary">2. Executive summary</h2>
    {summary_html}
    <h3>Compliance by domain</h3>
    {domain_table}

    <h2 id="results">3. Detailed results</h2>
    <p class="note">Each control is compared with the expected result defined in the control file.
    Rows marked in red are non-compliant, and rows marked in amber could not be evaluated.</p>
    {''.join(detail_html)}

    <h2 id="appendix">4. Appendices</h2>
    <p class="note">System inventory collected during the assessment. Times are shown in UTC.</p>
    {appendix_html}

    <footer>Generated on {esc(generated)} from the assessment data collected on {esc(info['timestamp'])}.</footer>
</main>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"Compliance results saved to {filename}.")


def main():
    # Argument parser to handle command line inputs
    parser = argparse.ArgumentParser(description="Generate security compliance reports based on XML data.")
    parser.add_argument("-c", "--control", required=True, help="Path to the control file (XML format)")
    parser.add_argument("-d", "--dump", required=True, help="Path to the dump file (XML format)")
    args = parser.parse_args()

    # Parse both XML files once
    dump_root = ET.parse(args.dump).getroot()
    controls_root = ET.parse(args.control).getroot()

    # Proceed with compliance checks
    compliance_results = check_all_compliance(dump_root, controls_root)

    # Save compliance results and system information to HTML
    save_to_html(compliance_results, dump_root)

    # Optionally save to CSV as well
    save_to_csv(compliance_results, dump_root)


# Run the script
if __name__ == "__main__":
    main()
