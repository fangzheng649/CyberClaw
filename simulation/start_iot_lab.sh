#!/bin/bash
# CyberClaw IoT Lab - Docker-based Simulation Environment
# Usage: wsl -e bash /mnt/d/臻荣/CyberClaw/simulation/start_iot_lab.sh
set -e

# Stop and remove old containers
echo "=== Cleaning up ==="
for name in Camera-HK-1 Camera-HK-2 Camera-DH-1 Camera-DH-2 \
            TempSensor-1 PressureSensor-2 SmartPlug-1 SmartPlug-2 \
            IoT-Gateway MQTT-Broker Nmap-Scanner; do
  docker rm -f "$name" 2>/dev/null || true
done

# Create network
docker network rm iot-lab 2>/dev/null || true
docker network create --driver bridge --subnet 10.0.0.0/24 iot-lab

# Start containers
echo "=== Starting IoT Lab ==="

# 4 IP Cameras
for i in 1 2 3 4; do
  case $i in
    1) name="Camera-HK-1"; ip="10.0.0.11"; port=8081 ;;
    2) name="Camera-HK-2"; ip="10.0.0.12"; port=8082 ;;
    3) name="Camera-DH-1"; ip="10.0.0.13"; port=8083 ;;
    4) name="Camera-DH-2"; ip="10.0.0.14"; port=8084 ;;
  esac
  docker run -d --name "$name" --hostname "$name" \
    --network iot-lab --ip "$ip" -p $port:80 \
    cyberclaw/camera:latest > /dev/null
  echo "  $name -> $ip"
done

# 2 Sensors
for i in 1 2; do
  case $i in
    1) name="TempSensor-1"; ip="10.0.0.21"; port=8091 ;;
    2) name="PressureSensor-2"; ip="10.0.0.22"; port=8092 ;;
  esac
  docker run -d --name "$name" --hostname "$name" \
    --network iot-lab --ip "$ip" -p $port:80 \
    cyberclaw/sensor:latest > /dev/null
  echo "  $name -> $ip"
done

# 2 Smart Plugs
for i in 1 2; do
  case $i in
    1) name="SmartPlug-1"; ip="10.0.0.31"; port=9071 ;;
    2) name="SmartPlug-2"; ip="10.0.0.32"; port=9072 ;;
  esac
  docker run -d --name "$name" --hostname "$name" \
    --network iot-lab --ip "$ip" -p $port:80 \
    cyberclaw/plug:latest > /dev/null
  echo "  $name -> $ip"
done

# Gateway
docker run -d --name "IoT-Gateway" --hostname "IoT-Gateway" \
  --network iot-lab --ip "10.0.0.1" -p 8060:80 \
  cyberclaw/gateway:latest > /dev/null
echo "  IoT-Gateway -> 10.0.0.1"

# MQTT Broker
docker run -d --name "MQTT-Broker" --hostname "MQTT-Broker" \
  --network iot-lab --ip "10.0.0.50" -p 1883:1883 \
  cyberclaw/mqtt-broker:latest > /dev/null
echo "  MQTT-Broker -> 10.0.0.50"

# Scanner
docker run -d --name "Nmap-Scanner" --hostname "Nmap-Scanner" \
  --network iot-lab --ip "10.0.0.100" --cap-add=NET_ADMIN \
  cyberclaw/scanner:latest > /dev/null
echo "  Nmap-Scanner -> 10.0.0.100"

sleep 3
echo ""
echo "=== Lab Ready ==="
echo "Cameras:    http://localhost:8081-8084"
echo "Sensors:    http://localhost:8091-8092"
echo "Plugs:      http://localhost:9071-9072"
echo "Gateway:    http://localhost:8060"
echo "MQTT:       localhost:1883"
echo ""
echo "Scan: docker exec Nmap-Scanner nmap -sn 10.0.0.0/24"
