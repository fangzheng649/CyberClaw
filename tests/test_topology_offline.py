"""real 模式拓扑过滤：离线(present=0)的真实设备不应返回给 HUD。

根因：按 S 断网时 device_offline 把设备从前端场景移除，但 async_get_topology 仍返回
这台离线设备(present=0, online=False)，刷新页面 buildTopology 又把它渲染回来 →
"删去的设备刷新后又出现"。修复：real 模式过滤掉 online=False 的非 mock 设备，与
device_offline 的移除一致。has_real 仍按"存在"判断(不按在线)，故断网不回退 mock。
"""
import pytest

from server.services import topology_service as ts


class _FakeBridge:
    def __init__(self, devices):
        self._devices = devices

    async def get_all_devices(self):
        return self._devices


def _dev(mac, name, ip, present, method="arp_table", dtype="camera", pos="[0,0,0]"):
    return {
        "devMac": mac, "devName": name, "devLastIP": ip, "devType": dtype,
        "devStatus": "secure", "devPresentLastScan": present,
        "devDiscoveryMethod": method, "devPos": pos, "devVendor": "", "devModel": "",
    }


@pytest.fixture(autouse=True)
def _restore_mode():
    saved = ts._mock_mode
    ts.reset_profile_cache()
    yield
    ts._mock_mode = saved
    ts.reset_profile_cache()


async def test_real_mode_excludes_offline_devices(monkeypatch):
    """离线真实设备(present=0)不应出现在拓扑，在线的真实设备保留。"""
    ts.set_mock_mode(False)
    devices = [
        _dev("60:a3:e3:61:81:0f", "TL-SG2210LPF", "192.168.1.1", present=1, dtype="switch"),
        _dev("8c:22:d2:41:09:08", "CAM-01", "192.168.1.11", present=0),   # 离线
        _dev("8c:22:d2:41:0b:ca", "CAM-02", "192.168.1.12", present=0),   # 离线
        _dev("00:00:00:00:00:aa", "Mock-X", "192.168.10.9", present=1, method="mock"),
    ]
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: _FakeBridge(devices))

    topo = await ts.async_get_topology()

    online_flags = {d.mac: d.online for d in topo.devices}
    macs = set(online_flags)
    # 在线真实设备保留
    assert "60:a3:e3:61:81:0f" in macs
    # 离线真实设备被过滤（不会刷新后重新出现）
    assert "8c:22:d2:41:09:08" not in macs
    assert "8c:22:d2:41:0b:ca" not in macs
    # mock 设备仍被过滤
    assert "00:00:00:00:00:aa" not in macs
    # 返回的设备全部在线（无离线残留在场景里）
    assert all(d.online for d in topo.devices)


async def test_real_mode_does_not_fall_back_to_mock_when_only_offline_reals(monkeypatch):
    """全部真实设备离线时仍不回退 mock（has_real 按"存在"而非"在线"判断）。

    否则断网会导致 HUD 跳回 19 台 mock 演示设备，违背用户选择的 A 行为。
    """
    ts.set_mock_mode(False)
    devices = [
        _dev("60:a3:e3:61:81:0f", "TL-SG2210LPF", "192.168.1.1", present=0, dtype="switch"),  # 离线
        _dev("00:00:00:00:00:aa", "Mock-X", "192.168.10.9", present=1, method="mock"),
    ]
    monkeypatch.setattr("server.services.nx_bridge.get_bridge", lambda: _FakeBridge(devices))

    topo = await ts.async_get_topology()

    # 真实设备离线 → 被过滤；mock 也被过滤 → devices 为空
    assert topo.devices == []
    # 但没有回退到 mock 演示拓扑（mock 设备没冒出来）
    assert all(d.discovery_method != "mock" for d in topo.devices)


async def test_mock_mode_returns_demo_topology_regardless_of_db(monkeypatch):
    """mock 模式直接返回 mock_topology.json 演示设备，不依赖 DB（手动 Shift 切换）。"""
    ts.set_mock_mode(True)
    # 即使 DB 里有真实在线设备，mock 模式也只返回演示拓扑
    monkeypatch.setattr(
        "server.services.nx_bridge.get_bridge",
        lambda: _FakeBridge([_dev("60:a3:e3:61:81:0f", "Real-Switch", "192.168.1.1",
                                  present=1, method="arp_table", dtype="switch")]),
    )
    topo = await ts.async_get_topology()
    # 返回的全是 mock 演示设备，不含 DB 里的真实设备
    assert all(d.discovery_method == "mock" for d in topo.devices)
    assert len(topo.devices) > 0  # mock_topology.json 有演示设备
