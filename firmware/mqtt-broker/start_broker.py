#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
CyberClaw IoT Lab — 本地 MQTT Broker 启动脚本
=================================================
纯本地 MQTT broker，监听 0.0.0.0:1883，允许匿名连接。
供 ESP32 发布遥测数据、CyberClaw 订阅监控。

用法：
    双击 start_broker.bat
    或命令行： python start_broker.py
停止：按 Ctrl+C
"""
import asyncio
import logging
import sys
import types
from dataclasses import asdict

# Python 3.11+ 移除了 asyncio.coroutine；老库（hbmqtt）依赖它，补个兼容垫片。
if not hasattr(asyncio, "coroutine"):
    asyncio.coroutine = types.coroutine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyberclaw-broker")


def create_broker():
    """根据已安装的库创建 broker 实例。

    amqtt（新）：直接用它的默认 BrokerConfig（已绑定 0.0.0.0:1883 + 匿名），
                 asdict() 转成 dict 喂给 Broker，字段名 100% 正确。
    hbmqtt（老）：用兼容老格式的 dict。
    """
    # 优先 amqtt
    try:
        from amqtt.broker import Broker
        from amqtt.contexts import BrokerConfig
        # amqtt 默认配置：listeners.default.bind='0.0.0.0:1883'，含匿名认证插件
        cfg = asdict(BrokerConfig())
        logger.info("使用 amqtt，配置取自默认 BrokerConfig")
        return Broker(cfg), "amqtt"
    except ImportError:
        pass
    # 回退 hbmqtt（仅老 Python 可用）
    try:
        from hbmqtt.broker import Broker
        cfg = {
            "listeners": {
                "default": {"type": "tcp"},
                "tcp-lan": {"type": "tcp", "bind": "0.0.0.0:1883"},
            },
            "auth": {"allow-anonymous": True},
            "sys_interval": 20,
        }
        logger.info("使用 hbmqtt")
        return Broker(cfg), "hbmqtt"
    except ImportError:
        return None, None


async def run():
    broker, which = create_broker()
    if broker is None:
        logger.error("未安装 MQTT broker 库。请执行：")
        logger.error("  pip install amqtt -i https://pypi.tuna.tsinghua.edu.cn/simple")
        sys.exit(1)

    await broker.start()

    print("=" * 55)
    print("  ✅ CyberClaw MQTT Broker 已启动")
    print(f"  broker 库: {which}")
    print("  监听地址: 0.0.0.0:1883")
    print("  匿名连接: 允许")
    print("  停止方式: 在此窗口按 Ctrl+C")
    print("=" * 55)
    print("等待 ESP32 / CyberClaw 连接...\n")
    print("（这个窗口要保持开着，关掉 broker 就停了）\n")

    try:
        await asyncio.Event().wait()  # 永久阻塞，保持 broker 运行
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await broker.shutdown()
        logger.info("Broker 已停止")


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n已退出")
