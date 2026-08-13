#!/bin/sh

set -eu

# ============================================================
# FreeBSD 15.1 OpenVPN Server Installer
# ============================================================

OPENVPN_DIR="/usr/local/etc/openvpn"
EASYRSA_DIR="${OPENVPN_DIR}/easy-rsa"
PKI_DIR="${EASYRSA_DIR}/pki"
EASYRSA="/usr/local/bin/easyrsa"

SERVER_CONF="${OPENVPN_DIR}/openvpn.conf"
PF_CONF="/etc/pf.conf"

VPN_NET="10.8.0.0"
VPN_MASK="255.255.255.0"

LAN_NET="172.16.10.0"
LAN_MASK="255.255.255.0"

WAN_IF="em0"
LAN_IF="em1"

VPN_SERVER_IP="192.168.88.176"
VPN_PORT="1194"

echo
echo "============================================================"
echo " FreeBSD 15.1 OpenVPN Server Installer"
echo "============================================================"
echo
echo " WAN interface : ${WAN_IF}"
echo " WAN IP        : ${VPN_SERVER_IP}"
echo " LAN interface : ${LAN_IF}"
echo " LAN network   : ${LAN_NET}/24"
echo " VPN network   : ${VPN_NET}/24"
echo " VPN port      : ${VPN_PORT}/udp"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run this script as root."
    exit 1
fi

# ------------------------------------------------------------
# Install packages
# ------------------------------------------------------------

echo "[+] Installing packages..."

pkg install -y openvpn easy-rsa

# ------------------------------------------------------------
# Directories
# ------------------------------------------------------------

echo "[+] Creating directories..."

mkdir -p "${OPENVPN_DIR}"
mkdir -p "${OPENVPN_DIR}/clients"

# ------------------------------------------------------------
# Easy-RSA
# ------------------------------------------------------------

echo "[+] Preparing Easy-RSA..."

if [ ! -d "${EASYRSA_DIR}" ]; then
    mkdir -p "${EASYRSA_DIR}"
fi

# Copy Easy-RSA files if not already present
if [ ! -f "${EASYRSA_DIR}/easyrsa" ]; then
    cp -R /usr/local/share/easy-rsa/* "${EASYRSA_DIR}/"
fi

chmod +x "${EASYRSA}"

# ------------------------------------------------------------
# Initialize PKI
# ------------------------------------------------------------

if [ -d "${PKI_DIR}" ]; then
    echo
    echo "[!] Existing PKI detected:"
    echo
    echo "    ${PKI_DIR}"
    echo
    echo "This script will NOT overwrite it."
    echo
    echo "If you intentionally want a new PKI, remove:"
    echo
    echo "    ${PKI_DIR}"
    echo
    exit 1
fi

cd "${EASYRSA_DIR}"

echo "[+] Initializing PKI..."

"${EASYRSA}" init-pki

echo "[+] Creating CA..."

EASYRSA_BATCH=1 "${EASYRSA}" build-ca nopass

# ------------------------------------------------------------
# Server certificate
# ------------------------------------------------------------

echo "[+] Creating server certificate..."

EASYRSA_BATCH=1 "${EASYRSA}" build-server-full server nopass

# ------------------------------------------------------------
# DH
# ------------------------------------------------------------

echo "[+] Generating DH parameters..."

"${EASYRSA}" gen-dh

# ------------------------------------------------------------
# TLS crypt key
# ------------------------------------------------------------

echo "[+] Generating tls-crypt key..."

openvpn --genkey tls-crypt "${PKI_DIR}/easyrsa-tls.key"

# ------------------------------------------------------------
# Copy server files
# ------------------------------------------------------------

echo "[+] Installing server certificates..."

mkdir -p "${OPENVPN_DIR}/pki"

cp "${PKI_DIR}/ca.crt" \
   "${OPENVPN_DIR}/pki/ca.crt"

cp "${PKI_DIR}/issued/server.crt" \
   "${OPENVPN_DIR}/pki/server.crt"

cp "${PKI_DIR}/private/server.key" \
   "${OPENVPN_DIR}/pki/server.key"

cp "${PKI_DIR}/dh.pem" \
   "${OPENVPN_DIR}/pki/dh.pem"

cp "${PKI_DIR}/easyrsa-tls.key" \
   "${OPENVPN_DIR}/pki/easyrsa-tls.key"

chmod 600 "${OPENVPN_DIR}/pki/server.key"
chmod 600 "${OPENVPN_DIR}/pki/easyrsa-tls.key"

# ------------------------------------------------------------
# OpenVPN server configuration
# ------------------------------------------------------------

echo "[+] Creating OpenVPN configuration..."

cat > "${SERVER_CONF}" <<EOF
############################################################
# OpenVPN Server - FreeBSD 15.1
############################################################

port ${VPN_PORT}
proto udp

dev tun

topology subnet

server ${VPN_NET} ${VPN_MASK}

# ----------------------------------------------------------
# Routing
# ----------------------------------------------------------

push "route ${LAN_NET} ${LAN_MASK}"

# ----------------------------------------------------------
# PKI
# ----------------------------------------------------------

ca ${OPENVPN_DIR}/pki/ca.crt
cert ${OPENVPN_DIR}/pki/server.crt
key ${OPENVPN_DIR}/pki/server.key

dh ${OPENVPN_DIR}/pki/dh.pem

# ----------------------------------------------------------
# TLS
# ----------------------------------------------------------

tls-crypt ${OPENVPN_DIR}/pki/easyrsa-tls.key

tls-version-min 1.2

verify-client-cert require
remote-cert-tls client

# ----------------------------------------------------------
# Crypto
# ----------------------------------------------------------

data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM

auth SHA256

# ----------------------------------------------------------
# Client handling
# ----------------------------------------------------------

keepalive 10 120

persist-key
persist-tun

user nobody
group nobody

# ----------------------------------------------------------
# Logging
# ----------------------------------------------------------

status /var/log/openvpn-status.log

verb 3
EOF

chmod 600 "${SERVER_CONF}"

# ------------------------------------------------------------
# Enable IP forwarding
# ------------------------------------------------------------

echo "[+] Enabling IPv4 forwarding..."

sysrc gateway_enable="YES"

# Apply immediately
sysctl net.inet.ip.forwarding=1

# ------------------------------------------------------------
# PF configuration
# ------------------------------------------------------------

echo "[+] Configuring PF..."

if [ -f "${PF_CONF}" ]; then
    cp "${PF_CONF}" "${PF_CONF}.backup.$(date +%Y%m%d%H%M%S)"
fi

cat > "${PF_CONF}" <<EOF
############################################################
# PF - FreeBSD OpenVPN
############################################################

ext_if="${WAN_IF}"
int_if="${LAN_IF}"

vpn_net="${VPN_NET}/24"
lan_net="${LAN_NET}/24"

set skip on lo

# ----------------------------------------------------------
# NAT VPN -> LAN
# ----------------------------------------------------------

nat on \$int_if from \$vpn_net to \$lan_net -> (\$int_if)

# ----------------------------------------------------------
# OpenVPN incoming
# ----------------------------------------------------------

pass in on \$ext_if proto udp to port ${VPN_PORT} keep state

# ----------------------------------------------------------
# VPN traffic
# ----------------------------------------------------------

pass in on tun0 from \$vpn_net to \$lan_net keep state

pass out on \$int_if from \$vpn_net to \$lan_net keep state

pass in on \$int_if from \$lan_net to \$vpn_net keep state

pass out on tun0 from \$lan_net to \$vpn_net keep state

# ----------------------------------------------------------
# Allow VPN client to communicate with FreeBSD itself
# ----------------------------------------------------------

pass in on tun0 from \$vpn_net to any keep state

# ----------------------------------------------------------
# Return traffic
# ----------------------------------------------------------

pass out on \$ext_if all keep state
pass out on \$int_if all keep state
EOF

# ------------------------------------------------------------
# Enable PF
# ------------------------------------------------------------

echo "[+] Enabling PF..."

sysrc pf_enable="YES"

# ------------------------------------------------------------
# Validate PF
# ------------------------------------------------------------

echo "[+] Checking PF configuration..."

pfctl -nf "${PF_CONF}"

# ------------------------------------------------------------
# Enable OpenVPN
# ------------------------------------------------------------

echo "[+] Enabling OpenVPN..."

sysrc openvpn_enable="YES"

# ------------------------------------------------------------
# Start PF
# ------------------------------------------------------------

echo "[+] Starting PF..."

service pf restart

# ------------------------------------------------------------
# Start OpenVPN
# ------------------------------------------------------------

echo "[+] Starting OpenVPN..."

service openvpn restart

# ------------------------------------------------------------
# Final verification
# ------------------------------------------------------------

echo
echo "============================================================"
echo " OpenVPN Server Installation Complete"
echo "============================================================"
echo
echo "Server IP      : ${VPN_SERVER_IP}"
echo "OpenVPN port   : ${VPN_PORT}/udp"
echo "VPN network    : ${VPN_NET}/24"
echo "LAN network    : ${LAN_NET}/24"
echo
echo "Configuration:"
echo
echo "  ${SERVER_CONF}"
echo
echo "PKI:"
echo
echo "  ${EASYRSA_DIR}"
echo
echo "Server certificate:"
echo
echo "  ${OPENVPN_DIR}/pki/server.crt"
echo
echo "Check service:"
echo
echo "  service openvpn status"
echo
echo "Check interface:"
echo
echo "  ifconfig tun0"
echo
echo "Check PF:"
echo
echo "  pfctl -sr"
echo "  pfctl -sn"
echo
echo "============================================================"
