import extract_msg
import os
import sys

def extract_msg_file(msg_path, output_dir="output"):
    if not os.path.exists(msg_path):
        print(f"[ERROR] File tidak ditemukan: {msg_path}")
        return

    # Load MSG
    msg = extract_msg.Message(msg_path)
    msg_subject = msg.subject or "no_subject"

    # Bikin nama folder aman
    safe_subject = "".join(c for c in msg_subject if c.isalnum() or c in (" ", "_")).rstrip()
    if not safe_subject:
        safe_subject = "no_subject"

    email_dir = os.path.join(output_dir, safe_subject)
    os.makedirs(email_dir, exist_ok=True)

    # Simpan isi email
    email_content = f"""FROM: {msg.sender}
TO: {msg.to}
CC: {msg.cc}
DATE: {msg.date}
SUBJECT: {msg.subject}

BODY:
{msg.body}
"""

    with open(os.path.join(email_dir, "email.txt"), "w", encoding="utf-8") as f:
        f.write(email_content.strip())

    print(f"[+] Email disimpan: {email_dir}/email.txt")

    # Simpan attachment
    if msg.attachments:
        for att in msg.attachments:
            filename = att.longFilename or att.shortFilename or "attachment"
            filepath = os.path.join(email_dir, filename)

            with open(filepath, "wb") as f:
                f.write(att.data)

            print(f"[+] Attachment: {filepath}")
    else:
        print("[i] Tidak ada attachment")

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract.py <file.msg> [output_folder]")
        sys.exit(1)

    msg_file = sys.argv[1]
    output_folder = sys.argv[2] if len(sys.argv) > 2 else "output"

    extract_msg_file(msg_file, output_folder)

if __name__ == "__main__":
    main()