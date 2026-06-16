#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
快速测试：订阅 ESP32 发布的 MQTT 消息
=====================================
用法：python test_subscribe.py

看到温湿度 JSON 数据，说明 ESP32 → broker 链路打通了。
注意：这个脚本连的是 127.0.0.1（本机），因为 broker 也跑在本机。
"""
import sys

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("缺少 paho-mqtt，正在安装...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install",
                          "paho-mqtt", "-i",
                          "https://pypi.tuna.tsinghua.edu.cn/simple"])
    import paho.mqtt.client as mqtt

BROKER = "127.0.0.1"
PORT = 1883
TOPIC = "cyberclaw/sensor/#"


def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print(f"✅ 已连接 broker: {BROKER}:{PORT}")
        client.subscribe(TOPIC)
        print(f"✅ 已订阅 topic: {TOPIC}")
        print("等待 ESP32 上报数据...（Ctrl+C 退出）\n")
    else:
        print(f"❌ 连接失败，状态码: {reason_code}")
        print("请确认 start_broker.py 正在运行")


def on_message(client, userdata, msg):
    print(f"[收到] {msg.topic}")
    print(f"        {msg.payload.decode('utf-8', errors='replace')}\n")


print(f"正在连接 {BROKER}:{PORT} ...")
client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id="cyberclaw-test-sub",
)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT, keepalive=60)
client.loop_forever()
