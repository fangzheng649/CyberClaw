# ESP32-S3 + DHT22 温湿度传感节点

CyberClaw IoT 实验室的 ESP32 固件。读取 DHT22 温湿度数据，通过 WiFi + MQTT 上报到笔记本上的 Mosquitto broker，由 CyberClaw 后端订阅监控。

## 硬件清单

| 部件 | 型号 |
|------|------|
| 主控 | ESP32-S3-DevKitC-1 |
| 传感器 | DHT22 模块（3针：VCC/OUT/GND） |

## 接线

```
DHT22模块          ESP32-S3-DevKitC-1
─────────          ───────────────────
 VCC  (+)   ─────→  3V3
 OUT  (数据) ─────→  GPIO4
 GND  (-)   ─────→  GND
```

> DHT22 模块已自带 10kΩ 上拉电阻，无需外接。

## 部署步骤

### 1. 安装 Mosquitto broker（在笔记本上）

1. 下载：https://mosquitto.org/download/ → Windows 64-bit
2. 安装到默认路径 `C:\Program Files\mosquitto\`
3. **以管理员身份** 编辑配置文件 `C:\Program Files\mosquitto\mosquitto.conf`，在文件末尾追加：

   ```
   # 允许局域网设备连接
   listener 1883 0.0.0.0
   allow_anonymous true
   ```

4. 以管理员身份重启 Mosquitto 服务：

   ```cmd
   net stop mosquitto
   net start mosquitto
   ```

5. 放行防火墙（管理员 cmd）：

   ```cmd
   netsh advfirewall firewall add rule name="Mosquitto MQTT" dir=in action=allow protocol=TCP localport=1883
   ```

### 2. 安装 Arduino IDE

1. 下载：https://www.arduino.cc/en/software → Windows
2. 安装后打开

### 3. 添加 ESP32 开发板支持

1. `文件 → 首选项` → 在「附加开发板管理器网址」填入：

   ```
   https://espressif.github.io/arduino-esp32/package_esp32_index.json
   ```

2. `工具 → 开发板 → 开发板管理器` → 搜索 `esp32` → 安装 **esp32 by Espressif Systems**

3. `工具 → 开发板 → esp32 → ESP32S3 Dev Module`

4. `工具 → 端口` 选 ESP32 连上的 COM 口

> ESP32-S3-DevKitC-1 用 USB-C 数据线连笔记本，注意要用**能传数据的线**（不是纯充电线）。

### 4. 安装库

`工具 → 管理库`，分别搜索并安装：

| 库名 | 作者 | 用途 |
|------|------|------|
| DHT sensor library | Adafruit | 读 DHT22 |
| PubSubClient | Nick O'Leary | MQTT 客户端 |

> 安装 DHT sensor library 时会提示安装依赖 `Adafruit Unified Sensor`，一并装上。

### 5. 修改固件配置

打开 `esp32-dht22.ino`，修改配置区的 4 项：

```cpp
const char* WIFI_SSID     = "你的WiFi名字";     // 实验室 WiFi
const char* WIFI_PASSWORD = "你的WiFi密码";
// MQTT_BROKER 改成运行 Mosquitto 的笔记本 IP（默认 192.168.1.100）
```

### 6. 烧录

1. ESP32 用 USB 连笔记本
2. 选好开发板 `ESP32S3 Dev Module` 和端口
3. 点 `上传`（→ 箭头按钮）
4. 烧录完成后打开 `工具 → 串口监视器`，波特率 `115200`，应看到：

   ```
   CyberClaw IoT Lab — ESP32-S3 + DHT22 节点
   正在连接 WiFi [xxx] ... 成功
     IP: 192.168.1.21
   正在连接 MQTT broker 192.168.1.100:1883 ... 成功
   发布 → cyberclaw/sensor/esp32-01/telemetry : {"device":"esp32-01","temp":25.4,...}
   ```

## 验证

### 方法 1：mosquitto_sub 命令行订阅

在笔记本 cmd 执行：

```cmd
"C:\Program Files\mosquitto\mosquitto_sub.exe" -h 192.168.1.100 -t "cyberclaw/sensor/esp32-01/telemetry" -v
```

应每 10 秒看到一条 JSON 数据。

### 方法 2：ping ESP32

```cmd
ping 192.168.1.21
```

## CyberClaw 集成

ESP32 启动后，CyberClaw 可通过：

1. **nmap 扫描**发现 `192.168.1.21` 这个新设备（开放 80 端口）
2. **MQTT 监控**订阅 `cyberclaw/sensor/esp32-01/#`，接收温湿度遥测并检测异常上报频率

## MQTT 数据格式

```json
{
  "device": "esp32-01",
  "temp": 25.4,
  "hum": 58.2,
  "ip": "192.168.1.21",
  "rssi": -52,
  "ts": 1718400000
}
```

| 字段 | 含义 |
|------|------|
| temp | 温度（℃） |
| hum | 相对湿度（%） |
| ip | ESP32 的 IP |
| rssi | WiFi 信号强度（dBm） |
| ts | 运行时长（秒） |

## 排错

| 现象 | 原因/解决 |
|------|-----------|
| WiFi 连接失败 | 检查 SSID/密码；ESP32 只支持 2.4GHz WiFi，**不支持 5GHz** |
| MQTT 连接失败（state=-2/-4） | Mosquitto 没启动 / 防火墙没放行 1883 / broker IP 写错 |
| DHT22 读取失败（NaN） | 接线松动；3V3/OUT/GND 接反；换一根数据线 |
| 烧录失败 | 选错开发板；USB 线是纯充电线；按住 BOOT 键再上传 |
| 串口监视器乱码 | 波特率没设成 115200 |
