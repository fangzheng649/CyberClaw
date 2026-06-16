/*
 * ============================================================================
 * CyberClaw IoT Lab — ESP32-S3 + DHT22 温湿度传感节点固件
 * ============================================================================
 * PlatformIO 版本（与 .ino 内容一致，开头加了 #include <Arduino.h>）
 *
 * 接线：DHT22 VCC→3V3, OUT→GPIO4, GND→GND
 * ============================================================================
 */
#include <Arduino.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>

// ==================== 配置区（已按你的环境填好）====================

// --- WiFi 配置（你的手机热点）---
const char* WIFI_SSID     = "iQOO Neo9";
const char* WIFI_PASSWORD = "20041129";

// --- 静态 IP（手机热点 DHCP 池不可预测，这里先用 DHCP，下面已注释掉静态配置）---
// 如果以后换到实验室路由器（192.168.1.x），取消下面注释并改用 WiFi.config()
IPAddress LOCAL_IP   (10, 168, 9, 200);
IPAddress GATEWAY    (10, 168, 9, 243);
IPAddress SUBNET     (255, 255, 255, 0);
IPAddress DNS_SERVER (10, 168, 9, 243);

// --- MQTT 配置（broker 跑在笔记本上，笔记本 WiFi IP 是 10.168.9.244）---
const char* MQTT_BROKER = "10.168.9.244";
const int   MQTT_PORT   = 1883;
const char* MQTT_TOPIC  = "cyberclaw/sensor/esp32-01/telemetry";

// --- 传感器配置 ---
#define DHT_PIN     4        // DHT22 数据线接 GPIO4
#define DHT_TYPE    DHT22    // 传感器型号
const long READ_INTERVAL_MS = 10000;   // 采样间隔 10 秒

// ==================== 配置区结束 ====================

DHT dht(DHT_PIN, DHT_TYPE);
WiFiClient espClient;
PubSubClient mqtt(espClient);

unsigned long lastRead = 0;
bool ledState = false;

void connectWiFi() {
  Serial.print("正在连接 WiFi [");
  Serial.print(WIFI_SSID);
  Serial.print("] ...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  // 手机热点用 DHCP，不用静态 IP；换到实验室路由器时可取消下面这行注释
  // WiFi.config(LOCAL_IP, GATEWAY, SUBNET, DNS_SERVER);

  int waited = 0;
  while (WiFi.status() != WL_CONNECTED && waited < 40) {
    delay(500);
    Serial.print(".");
    waited++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(" 成功");
    Serial.print("  ESP32 IP: ");
    Serial.println(WiFi.localIP());
    Serial.print("  RSSI: ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");
  } else {
    Serial.println(" 失败！将重试...");
  }
}

void connectMQTT() {
  Serial.print("连接 MQTT broker ");
  Serial.print(MQTT_BROKER);
  Serial.print(":");
  Serial.print(MQTT_PORT);
  Serial.print(" ...");

  String clientId = "esp32-01-" + String((uint32_t)ESP.getEfuseMac(), HEX);
  if (mqtt.connect(clientId.c_str())) {
    Serial.println(" 成功");
  } else {
    Serial.print(" 失败，状态码=");
    Serial.println(mqtt.state());
  }
}

void readAndPublish() {
  float temp = dht.readTemperature();
  float hum  = dht.readHumidity();

  if (isnan(temp) || isnan(hum)) {
    Serial.println("⚠ DHT22 读取失败（NaN），跳过本次");
    return;
  }

  char payload[256];
  // payload 含 mac（供 CyberClaw 后端 MQTT 自动发现写入 Devices 表，作设备唯一标识）
  snprintf(payload, sizeof(payload),
           "{\"mac\":\"%s\",\"device\":\"esp32-01\",\"temp\":%.1f,\"hum\":%.1f,\"ip\":\"%s\",\"rssi\":%d,\"ts\":%lu}",
           WiFi.macAddress().c_str(),
           temp, hum,
           WiFi.localIP().toString().c_str(),
           WiFi.RSSI(),
           millis() / 1000);

  Serial.print("发布 → ");
  Serial.print(MQTT_TOPIC);
  Serial.print(" : ");
  Serial.println(payload);

  if (!mqtt.publish(MQTT_TOPIC, payload)) {
    Serial.println("⚠ 发布失败（broker 可能断开）");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println();
  Serial.println("============================================");
  Serial.println("CyberClaw IoT Lab — ESP32-S3 + DHT22 节点");
  Serial.println("============================================");

  pinMode(48, OUTPUT);        // 板载 LED（心跳指示）
  dht.begin();
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setBufferSize(512);

  connectWiFi();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }
  if (WiFi.status() == WL_CONNECTED && !mqtt.connected()) {
    connectMQTT();
  }
  mqtt.loop();

  unsigned long now = millis();
  if (now - lastRead >= READ_INTERVAL_MS) {
    lastRead = now;
    if (mqtt.connected()) {
      readAndPublish();
    } else {
      Serial.println("MQTT 未连接，跳过采样");
    }
  }

  static unsigned long lastBlink = 0;
  if (now - lastBlink >= 1000) {
    lastBlink = now;
    ledState = !ledState;
    digitalWrite(48, ledState);
  }
}
