#!/bin/bash

# --- Configuration ---
CA_PASSWORD="admin"
COUNTRY="VN"
STATE="Hanoi"
CITY="Hanoi"
ORGANIZATION="My IOT Org"
ORG_UNIT="IOT Devices"

# --- Certificate Authority ---
CA_CN="My IOT CA Root"

# --- Server Details ---
SERVER_CN="10.185.90.215"

# --- Client Details ---
CLIENT_CN_1="sensor1"
CLIENT_CN_2="sensor2"
CLIENT_CN_3="sensor3"
CLIENT_CN_4="sensor4"

# --- Define Path --- 
SCRIPT_DIR="$(pwd)"
GATEWAY_CERTS_DIR="$SCRIPT_DIR/gateway/certs"
GATEWAY_DOCKER_COMPOSE_DIR="$SCRIPT_DIR/gateway"
FAKE_SENSOR_DOCKER_COMPOSE_DIR="$SCRIPT_DIR/fake_sensor"
SENSOR1_DIR="$SCRIPT_DIR/fake_sensor/build/sensor1"
SENSOR2_DIR="$SCRIPT_DIR/fake_sensor/build/sensor2"
SENSOR3_DIR="$SCRIPT_DIR/fake_sensor/build/sensor3"
SENSOR4_DIR="$SCRIPT_DIR/fake_sensor/build/sensor4"

# --- Delete Old Cert --- 
rm -f "$GATEWAY_CERTS_DIR"/*.{crt,key,pem,srl} 2>/dev/null
rm -f "$SENSOR1_DIR"/*.{crt,key,srl} 2>/dev/null
rm -f "$SENSOR2_DIR"/*.{crt,key,srl} 2>/dev/null
rm -f "$SENSOR3_DIR"/*.{crt,key,srl} 2>/dev/null
rm -f "$SENSOR4_DIR"/*.{crt,key,srl} 2>/dev/null

# --- Create directories if not exist ---
mkdir -p "$GATEWAY_CERTS_DIR" "$SENSOR1_DIR" "$SENSOR2_DIR" "$SENSOR3_DIR" "$SENSOR4_DIR"

# --- CA Generation ---
echo "--- Generating CA key and certificate ---"
openssl genrsa -aes256 -passout pass:$CA_PASSWORD -out ca.key 2048
openssl req -new -x509 -days 3650 -key ca.key -passin pass:$CA_PASSWORD -out ca.crt \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORG_UNIT/CN=$CA_CN"

# --- Server Certificate Generation ---
echo "--- Generating Server key and certificate ---"
openssl genrsa -out server.key 2048
openssl req -new -out server.csr -key server.key \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=Broker/CN=$SERVER_CN"
# Add SAN so modern TLS clients (OpenSSL 1.1+, mosquitto) can verify the server IP
echo "subjectAltName=IP:$SERVER_CN" > server_ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -passin pass:$CA_PASSWORD \
  -CAcreateserial -out server.crt -days 730 -extfile server_ext.cnf
rm -f server_ext.cnf

cat server.crt server.key > server.pem

cp server.crt server.key server.pem ca.crt "$GATEWAY_CERTS_DIR/"

# -- Restart MQTT Broker service --- 
cd $GATEWAY_DOCKER_COMPOSE_DIR
docker compose restart mosquitto haproxy
cd $SCRIPT_DIR

# --- Client 1 Certificate Generation ---
echo "--- Generating Client key and certificate for '$CLIENT_CN_1' ---"
openssl genrsa -out client.key 2048
openssl req -new -out client.csr -key client.key \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=Sensors/CN=$CLIENT_CN_1"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -passin pass:$CA_PASSWORD -CAcreateserial -out client.crt -days 730

cp ca.crt client.crt client.key "$SENSOR1_DIR/"

# --- Client 2 Certificate Generation ---
echo "--- Generating Client key and certificate for '$CLIENT_CN_2' ---"
openssl genrsa -out client.key 2048
openssl req -new -out client.csr -key client.key \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=Sensors/CN=$CLIENT_CN_2"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -passin pass:$CA_PASSWORD -CAcreateserial -out client.crt -days 730

cp ca.crt client.crt client.key "$SENSOR2_DIR/"

# --- Client 3 Certificate Generation ---
echo "--- Generating Client key and certificate for '$CLIENT_CN_3' ---"
openssl genrsa -out client.key 2048
openssl req -new -out client.csr -key client.key \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=Sensors/CN=$CLIENT_CN_3"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -passin pass:$CA_PASSWORD -CAcreateserial -out client.crt -days 730

cp ca.crt client.crt client.key "$SENSOR3_DIR/"

# --- Client 4 Certificate Generation ---
echo "--- Generating Client key and certificate for '$CLIENT_CN_4' ---"
openssl genrsa -out client.key 2048
openssl req -new -out client.csr -key client.key \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=Sensors/CN=$CLIENT_CN_4"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -passin pass:$CA_PASSWORD -CAcreateserial -out client.crt -days 730

cp ca.crt client.crt client.key "$SENSOR4_DIR/"

# --- Grant Permission ---
chown -R 1883:1883 "$GATEWAY_CERTS_DIR" 2>/dev/null || true
chmod 644 "$GATEWAY_CERTS_DIR"/*.crt "$GATEWAY_CERTS_DIR"/*.pem 2>/dev/null
chmod 600 "$GATEWAY_CERTS_DIR"/*.key 2>/dev/null

for dir in "$SENSOR1_DIR" "$SENSOR2_DIR" "$SENSOR3_DIR" "$SENSOR4_DIR"; do
    [ -d "$dir" ] && {
        chown -R 1880:1880 "$dir"/*.crt 2>/dev/null
    }
done

# --- Rebuild to Update Cert for Sensor ---
cd $FAKE_SENSOR_DOCKER_COMPOSE_DIR
docker compose build 
cd $SCRIPT_DIR

# --- Delete All Cert at the end ---
rm -f ./*.{crt,key,pem,srl,csr} 2>/dev/null