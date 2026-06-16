"""探查 amqtt 的 BrokerConfig 有效字段名（解决 dacite 严格校验问题）。"""
import typing
from dataclasses import fields, is_dataclass

try:
    from amqtt.contexts import BrokerConfig
except ImportError:
    print("amqtt 未安装")
    raise SystemExit(1)


def describe(cls, indent=0):
    pad = "  " * indent
    try:
        hints = typing.get_type_hints(cls)
    except Exception:
        hints = {}
    for f in fields(cls):
        t = hints.get(f.name, f.type)
        origin = typing.get_origin(t)
        args = typing.get_args(t)
        print(f"{pad}- {f.name}   (类型: {t})")
        if is_dataclass(t):
            describe(t, indent + 1)
        elif origin is dict and args and is_dataclass(args[-1]):
            print(f"{pad}  ↳ 它的值是 {args[-1].__name__}，字段如下:")
            describe(args[-1], indent + 2)


print("=" * 55)
print("amqtt BrokerConfig 认可的字段结构：")
print("=" * 55)
describe(BrokerConfig)

print()
print("=" * 55)
print("尝试直接实例化默认 BrokerConfig：")
print("=" * 55)
try:
    cfg = BrokerConfig()
    print("成功！默认配置：")
    print(cfg)
except Exception as e:
    print(f"不能直接实例化: {e}")
