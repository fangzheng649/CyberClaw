from ..models.schemas import DeviceResponse, LinkResponse, TopologyResponse


DEVICES = [
    DeviceResponse(id="router-1", name="Router-1", type="router", ip="10.0.1.1", mac="00:1A:2B:3C:4D:01", status="secure", pos=[-12, 0, -8]),
    DeviceResponse(id="router-2", name="Router-2", type="router", ip="10.0.2.1", mac="00:1A:2B:3C:4D:02", status="secure", pos=[12, 0, -8]),
    DeviceResponse(id="switch-core", name="Switch-Core", type="switch", ip="10.0.0.1", mac="00:1A:2B:3C:4D:10", status="secure", pos=[0, 0, 0]),
    DeviceResponse(id="camera-1", name="Camera-1", type="camera", ip="10.0.0.101", mac="AA:BB:CC:01:01:01", status="secure", pos=[-8, 0, 10], vendor="Hikvision", model="DS-2CD2142"),
    DeviceResponse(id="camera-2", name="Camera-2", type="camera", ip="10.0.0.102", mac="AA:BB:CC:01:01:02", status="secure", pos=[-3, 0, 12], vendor="Hikvision", model="DS-2CD2142"),
    DeviceResponse(id="camera-3", name="Camera-3", type="camera", ip="10.0.0.103", mac="AA:BB:CC:01:01:03", status="secure", pos=[3, 0, 12], vendor="Dahua", model="IPC-HDW2431"),
    DeviceResponse(id="camera-4", name="Camera-4", type="camera", ip="10.0.0.104", mac="AA:BB:CC:01:01:04", status="secure", pos=[8, 0, 10], vendor="Dahua", model="IPC-HDW2431"),
    DeviceResponse(id="sensor-1", name="TempSensor-1", type="sensor", ip="10.0.0.201", mac="DD:EE:FF:02:01:01", status="secure", pos=[-6, 0, 18], vendor="Siemens", model="SITRANS TH400"),
    DeviceResponse(id="sensor-2", name="PressureSensor-2", type="sensor", ip="10.0.0.202", mac="DD:EE:FF:02:01:02", status="secure", pos=[6, 0, 18], vendor="Honeywell", model="XLS-100"),
    DeviceResponse(id="plug-1", name="SmartPlug-1", type="plug", ip="10.0.0.301", mac="11:22:33:03:01:01", status="secure", pos=[-10, 0, 6], vendor="TP-Link", model="HS110"),
    DeviceResponse(id="plug-2", name="SmartPlug-2", type="plug", ip="10.0.0.302", mac="11:22:33:03:01:02", status="secure", pos=[10, 0, 6], vendor="TP-Link", model="HS110"),
    DeviceResponse(id="admin-pc", name="Admin-PC", type="pc", ip="10.0.0.10", mac="55:66:77:04:01:01", status="secure", pos=[0, 0, -14]),
    DeviceResponse(id="kali", name="Kali-Attacker", type="attacker", ip="10.0.1.100", mac="66:66:66:66:66:66", status="secure", pos=[-20, 0, -18]),
    DeviceResponse(id="server", name="FileServer", type="server", ip="10.0.0.5", mac="77:88:99:05:01:01", status="secure", pos=[0, 0, 8]),
    DeviceResponse(id="gateway", name="IoT-Gateway", type="gateway", ip="10.0.0.254", mac="88:99:AA:06:01:01", status="secure", pos=[0, 0, -4]),
]

LINKS = [
    LinkResponse(from_="router-1", to="switch-core"),
    LinkResponse(from_="router-2", to="switch-core"),
    LinkResponse(from_="switch-core", to="camera-1"),
    LinkResponse(from_="switch-core", to="camera-2"),
    LinkResponse(from_="switch-core", to="camera-3"),
    LinkResponse(from_="switch-core", to="camera-4"),
    LinkResponse(from_="switch-core", to="sensor-1"),
    LinkResponse(from_="switch-core", to="sensor-2"),
    LinkResponse(from_="switch-core", to="plug-1"),
    LinkResponse(from_="switch-core", to="plug-2"),
    LinkResponse(from_="switch-core", to="admin-pc"),
    LinkResponse(from_="router-1", to="kali"),
    LinkResponse(from_="switch-core", to="server"),
    LinkResponse(from_="switch-core", to="gateway"),
    LinkResponse(from_="router-1", to="router-2"),
]


def get_topology() -> TopologyResponse:
    return TopologyResponse(devices=DEVICES, links=LINKS)


def get_device(device_id: str) -> DeviceResponse | None:
    return next((d for d in DEVICES if d.id == device_id), None)
