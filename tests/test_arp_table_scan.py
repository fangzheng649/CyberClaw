"""ARP 表扫描测试 —— Windows 非管理员下的可靠设备发现。

根因：_sync_scan 依赖 arp-scan（未安装）与 nmap -sn（在本机既 208s 超时又漏掉
摄像头），且 process_scan 强制要求 MAC。改用"并行 ICMP ping-sweep + arp -a"
读取系统 ARP 表获取 IP→MAC，能稳定发现所有响应 ICMP 的主机（含摄像头）。
"""
import pytest

from server.services import scan_service as ss


# 真实抓取的本机 `arp -a` 输出（多接口）。目标网段 192.168.1.0/24。
REAL_ARP_A = """
Interface: 192.168.1.100 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           60-a3-e3-61-81-0f     dynamic
  192.168.1.11          8c-22-d2-41-09-08     dynamic
  192.168.1.12          8c-22-d2-41-0b-ca     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  192.168.254.2         8c-22-d2-41-09-08     dynamic
  192.168.254.5         8c-22-d2-41-0b-ca     dynamic
  224.0.0.2             01-00-5e-00-00-02     static
  224.0.0.251           01-00-5e-00-00-fb     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 10.112.233.244 --- 0xa
  Internet Address      Physical Address      Type
  10.112.233.225        8e-4c-ed-8b-30-b9     dynamic
  10.112.233.255        ff-ff-ff-ff-ff-ff     static
"""


def test_parse_arp_output_finds_only_in_subnet_unicast():
    import ipaddress
    net = ipaddress.ip_network("192.168.1.0/24")
    pairs = ss._parse_arp_output(REAL_ARP_A, net)
    by_ip = dict(pairs)

    # 三台真实设备（交换机 + 两摄像头）都在
    assert by_ip["192.168.1.1"] == "60:a3:e3:61:81:0f"
    assert by_ip["192.168.1.11"] == "8c:22:d2:41:09:08"
    assert by_ip["192.168.1.12"] == "8c:22:d2:41:0b:ca"

    # 广播 .255（MAC ff-ff-...）被排除
    assert "192.168.1.255" not in by_ip
    # 其它网段（摄像头在 192.168.254.x 的次地址、10.x）被排除
    assert "192.168.254.2" not in by_ip
    assert "10.112.233.225" not in by_ip
    # 组播 224.x / 239.x 被排除（IP 也不在网段）
    assert "224.0.0.251" not in by_ip
    assert len(by_ip) == 3


def test_parse_arp_output_excludes_multicast_mac():
    import ipaddress
    # 01-xx / 33-xx / ff-xx 首字节为奇数 → 组播/广播，即使 IP 在网段也要排除
    text = (
        "  192.168.1.5           01-00-5e-00-00-01     static\n"
        "  192.168.1.6           33-33-00-00-00-01     static\n"
        "  192.168.1.7           00-11-22-33-44-55     dynamic\n"
    )
    net = ipaddress.ip_network("192.168.1.0/24")
    by_ip = dict(ss._parse_arp_output(text, net))
    assert by_ip == {"192.168.1.7": "00:11:22:33:44:55"}


def test_arp_table_scan_returns_enriched_devices(monkeypatch):
    ping_count = {"n": 0}

    def fake_run(cmd, *a, **k):
        if cmd and cmd[0] == "ping":
            ping_count["n"] += 1
        return None

    def fake_check_output(cmd, *a, **k):
        if cmd and cmd[0] == "arp":
            return REAL_ARP_A
        raise FileNotFoundError()

    monkeypatch.setattr(ss.subprocess, "run", fake_run)
    monkeypatch.setattr(ss.subprocess, "check_output", fake_check_output)

    res = ss._arp_table_scan("192.168.1.0/24")
    by_ip = {r["ip"]: r for r in res}

    assert "192.168.1.1" in by_ip and "192.168.1.11" in by_ip and "192.168.1.12" in by_ip
    assert by_ip["192.168.1.1"]["mac"] == "60:a3:e3:61:81:0f"
    assert by_ip["192.168.1.1"]["method"] == "arp_table"
    assert by_ip["192.168.1.1"]["scanSourcePlugin"] == "ARPTABLE"
    # 厂商经 OUI 回填（非 "Unknown" 占位；空串表示查不到也属诚实）
    assert "vendor" in by_ip["192.168.1.1"]
    # 确实做了 ping-sweep（populates ARP cache）
    assert ping_count["n"] > 0


def test_arp_table_scan_invalid_subnet_returns_empty():
    assert ss._arp_table_scan("not-a-network") == []


def test_sync_scan_does_not_fall_back_to_nmap_on_empty_arp_table(monkeypatch):
    """断网/空网段：arp_table 返回 [] 时，_sync_scan 绝不能再兜底跑 nmap -sn。

    本机 nmap -sn 扫一个无响应网段要 ~120s 才超时 → trigger_scan 挂起 → 用户按 S
    后迟迟看不到"发现 N 台"。arp_table 已经执行过（即便没扫到设备），其空结果就是
    事实，不应再用更慢更不可靠的 nmap 去推翻它。
    """
    import time
    svc = ss.ScanService()
    monkeypatch.setattr(ss, "_arp_table_scan", lambda subnet: [])
    nmap_calls = {"n": 0}
    real_check_output = ss.subprocess.check_output

    def spy(cmd, *a, **k):
        if cmd and cmd[0] == "nmap":
            nmap_calls["n"] += 1
            return ""  # 不真跑 nmap（否则测试会挂 120s）
        return real_check_output(cmd, *a, **k)

    monkeypatch.setattr(ss.subprocess, "check_output", spy)

    t = time.time()
    res = svc._sync_scan("192.168.99.0/24")
    dt = time.time() - t

    assert res == []
    assert nmap_calls["n"] == 0, "arp_table 已执行(即使空)就不该再兜底 nmap"
    assert dt < 5, f"空结果应在几秒内返回，实际 {dt:.1f}s（说明又在跑 nmap）"


async def test_process_results_empty_runs_pipeline_for_presence(monkeypatch):
    """空扫描结果也要跑 process 管线。

    populate([]) 清空 CurrentScan，process_scan_results 的 presence 阶段据此把本次
    未扫到的真实设备标记为离线(Device Down) → 广播 device_offline，让断网时 HUD 能
    反映设备失联。若空结果直接 return，断网后设备永远不掉线、HUD 毫无反馈。
    """
    svc = ss.ScanService()
    called = {"populate": False, "process": False}

    async def fake_populate(results, source="SCAN"):
        called["populate"] = True

    async def fake_process():
        called["process"] = True
        return []

    monkeypatch.setattr("server.services.process_scan.populate_current_scan", fake_populate)
    monkeypatch.setattr("server.services.process_scan.process_scan_results", fake_process)

    await svc._process_results([])

    assert called["populate"] is True, "空结果也应 populate（清空 CurrentScan）"
    assert called["process"] is True, "空结果也应跑 process（presence → 设备离线）"
