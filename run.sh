# Assign an IP address to local loopback
ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1   kms.ap-southeast-1.amazonaws.com" >> /etc/hosts


# AWS metadata proxy TCP:127.0.0.1:7001 -> VSOCK:3:7001
socat TCP-LISTEN:7001,fork,reuseaddr VSOCK-CONNECT:3:7001 &

# AWS kms proxy  TCP:127.0.0.1:443 -> VSOCK:3:7002
socat TCP-LISTEN:443,fork,reuseaddr VSOCK-CONNECT:3:7002 &

# API service proxy VSOCK:<enclave-cid>:8001 -> TCP:127.0.0.1:8002
socat VSOCK-LISTEN:8001,fork,reuseaddr TCP:127.0.0.1:8002 &

/app/enclave_signer