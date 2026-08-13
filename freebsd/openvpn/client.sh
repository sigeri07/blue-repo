#!/bin/sh

set -eu

# ============================================================
# FreeBSD OpenVPN Client Generator
# ============================================================

if [ "$#" -ne 1 ]; then
    echo
    echo "Usage:"
    echo
    echo "  $0 <CLIENT-NAME>"
    echo
    echo "Example:"
    echo
    echo "  $0 indra"
    echo
    exit 1
fi

CLIENT_NAME="$1"

OPENVPN_DIR="/usr/local/etc/openvpn"
EASYRSA_DIR="${OPENVPN_DIR}/easy-rsa"
PKI_DIR="${EASYRSA_DIR}/pki"
EASYRSA="/usr/local/bin/easyrsa"

CLIENT_DIR="${OPENVPN_DIR}/clients/${CLIENT_NAME}"

VPN_SERVER="192.168.88.176"
VPN_PORT="1194"

echo
echo "============================================================"
echo " OpenVPN Client Generator"
echo "============================================================"
echo
echo "Client : ${CLIENT_NAME}"
echo "Server : ${VPN_SERVER}:${VPN_PORT}"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run this script as root."
    exit 1
fi

# ------------------------------------------------------------
# Check Easy-RSA
# ------------------------------------------------------------

if [ ! -x "${EASYRSA}" ]; then
    echo "[!] Easy-RSA not found:"
    echo
    echo "    ${EASYRSA}"
    exit 1
fi

# ------------------------------------------------------------
# Check PKI
# ------------------------------------------------------------

if [ ! -f "${PKI_DIR}/ca.crt" ]; then
    echo "[!] CA not found."
    echo
    echo "Run server.sh first."
    exit 1
fi

if [ ! -f "${PKI_DIR}/issued/server.crt" ]; then
    echo "[!] Server certificate not found."
    exit 1
fi

if [ ! -f "${PKI_DIR}/easyrsa-tls.key" ]; then
    echo "[!] tls-crypt key not found."
    exit 1
fi

# ------------------------------------------------------------
# Check existing client
# ------------------------------------------------------------

if [ -d "${CLIENT_DIR}" ]; then
    echo
    echo "[!] Client already exists:"
    echo
    echo "    ${CLIENT_DIR}"
    echo
    echo "Aborting."
    exit 1
fi

mkdir -p "${CLIENT_DIR}"

cd "${EASYRSA_DIR}"

# ------------------------------------------------------------
# Generate client certificate
# ------------------------------------------------------------

echo "[+] Generating certificate for ${CLIENT_NAME}..."

EASYRSA_BATCH=1 "${EASYRSA}" build-client-full "${CLIENT_NAME}" nopass

CLIENT_CERT="${PKI_DIR}/issued/${CLIENT_NAME}.crt"
CLIENT_KEY="${PKI_DIR}/private/${CLIENT_NAME}.key"
CA_CERT="${PKI_DIR}/ca.crt"
TLS_KEY="${PKI_DIR}/easyrsa-tls.key"

# ------------------------------------------------------------
# Verify certificate
# ------------------------------------------------------------

echo "[+] Verifying client certificate..."

openssl verify \
    -CAfile "${CA_CERT}" \
    "${CLIENT_CERT}"

# ------------------------------------------------------------
# Verify EKU
# ------------------------------------------------------------

echo "[+] Checking client EKU..."

if ! openssl x509 \
    -in "${CLIENT_CERT}" \
    -noout -text |
    grep -q "TLS Web Client Authentication"
then
    echo
    echo "[!] Client certificate does not contain"
    echo "    TLS Web Client Authentication"
    exit 1
fi

echo "[+] Client EKU OK."

# ------------------------------------------------------------
# Create standalone OVPN
# ------------------------------------------------------------

echo "[+] Creating standalone .ovpn..."

OVPN_FILE="${CLIENT_DIR}/${CLIENT_NAME}.ovpn"

cat > "${OVPN_FILE}" <<EOF
############################################################
# OpenVPN Client
# Client: ${CLIENT_NAME}
############################################################

client

dev tun
proto udp

remote ${VPN_SERVER} ${VPN_PORT}

resolv-retry infinite
nobind

persist-key
persist-tun

# ----------------------------------------------------------
# Server certificate validation
# ----------------------------------------------------------

remote-cert-tls server

# ----------------------------------------------------------
# Crypto
# ----------------------------------------------------------

data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM

auth SHA256

tls-version-min 1.2

# ----------------------------------------------------------
# Logging
# ----------------------------------------------------------

verb 3

# ----------------------------------------------------------
# CA
# ----------------------------------------------------------

<ca>
$(cat "${CA_CERT}")
</ca>

# ----------------------------------------------------------
# Client certificate
# ----------------------------------------------------------

<cert>
$(cat "${CLIENT_CERT}")
</cert>

# ----------------------------------------------------------
# Client private key
# ----------------------------------------------------------

<key>
$(cat "${CLIENT_KEY}")
</key>

# ----------------------------------------------------------
# TLS Crypt
# ----------------------------------------------------------

<tls-crypt>
$(cat "${TLS_KEY}")
</tls-crypt>
EOF

chmod 600 "${OVPN_FILE}"

# ------------------------------------------------------------
# Validate generated OVPN
# ------------------------------------------------------------

echo "[+] Checking generated configuration..."

openvpn \
    --config "${OVPN_FILE}" \
    --test-crypto 2>/dev/null || true

# ------------------------------------------------------------
# Final
# ------------------------------------------------------------

echo
echo "============================================================"
echo " Client Created Successfully"
echo "============================================================"
echo
echo "Client:"
echo
echo "  ${CLIENT_NAME}"
echo
echo "Configuration:"
echo
echo "  ${OVPN_FILE}"
echo
echo "Give ONLY this file to the client:"
echo
echo "  ${CLIENT_NAME}.ovpn"
echo
echo "The CA, certificate, private key and tls-crypt key"
echo "are embedded inside the .ovpn file."
echo
echo "============================================================"
