"""SNMP service for CyberClaw — device info queries, trap reception, and topology discovery.

Uses pysnmp v7 (pure Python, no system dependencies).
- get_device_info(): query sysDescr, sysName, ifTable via SNMP GET/WALK
- discover_topology(): ARP + bridge table walk for topology mapping
- Trap receiver: listens on non-privileged port 1162
"""
import asyncio
import logging
import re
import socket
import subprocess
from collections import deque
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

MAX_TRAPS = 500

_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
_OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
_OID_SYSUPTIME = "1.3.6.1.2.1.1.3.0"
_OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"


def _check_pysnmp():
    try:
        from pysnmp.hlapi.v3arch.asyncio.cmdgen import SnmpEngine  # noqa: F401
        return True
    except ImportError:
        return False


class SNMPService:
    def __init__(self, trap_port: int = 1162):
        self.trap_port = trap_port
        self._trap_running = False
        self._traps: deque[dict] = deque(maxlen=MAX_TRAPS)
        self._broadcast_fn = None
        self._trap_sock: Optional[socket.socket] = None
        self._trap_task: Optional[asyncio.Task] = None

    def set_broadcast(self, fn):
        self._broadcast_fn = fn

    async def get_device_info(self, ip: str, community: str = "public",
                              version: str = "2c", port: int = 161) -> dict:
        """Query device info via SNMP GET/WALK using pysnmp v7."""
        if not _check_pysnmp():
            return {"status": "unavailable", "message": "pysnmp not installed"}

        from pysnmp.hlapi.v3arch.asyncio.cmdgen import (
            SnmpEngine, CommunityData, ContextData, ObjectType, get_cmd, walk_cmd,
        )
        from pysnmp.hlapi.v3arch.asyncio.transport import UdpTransportTarget
        from pysnmp.smi.rfc1902 import ObjectIdentity

        result = {"ip": ip, "reachable": False}
        engine = SnmpEngine()
        mp_model = 1 if version == "2c" else 0

        try:
            target = await UdpTransportTarget.create((ip, port), timeout=3.0, retries=1)
            auth = CommunityData(community, mpModel=mp_model)
            ctx = ContextData()

            # SNMP GET for system OIDs
            oids = [
                (_OID_SYSDESCR, "sys_descr"),
                (_OID_SYSNAME, "sys_name"),
                (_OID_SYSUPTIME, "sys_uptime"),
            ]

            for oid, key in oids:
                error_indication, error_status, _, var_binds = await get_cmd(
                    engine, auth, target, ctx,
                    ObjectType(ObjectIdentity(oid)),
                )
                if error_indication or error_status:
                    continue
                for vb in var_binds:
                    result[key] = str(vb[1])
                    result["reachable"] = True

            # SNMP WALK for interface descriptions
            interfaces = []
            async for (error_indication, error_status, _, var_bind_table) in walk_cmd(
                engine, auth, target, ctx,
                ObjectType(ObjectIdentity(_OID_IFDESCR)),
            ):
                if error_indication or error_status:
                    break
                for vb in var_bind_table:
                    idx = str(vb[0]).split(".")[-1]
                    interfaces.append({"index": idx, "descr": str(vb[1])})

            if interfaces:
                result["interfaces"] = interfaces

        except asyncio.TimeoutError:
            result["error"] = "SNMP query timed out"
        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"SNMP query error for {ip}: {e}")

        return result

    async def start_trap_receiver(self) -> dict:
        """Start a lightweight UDP trap listener on non-privileged port.

        Uses a raw UDP socket to receive SNMP trap packets,
        rather than pysnmp's complex dispatcher (simpler and more reliable).
        """
        if self._trap_running:
            return {"status": "already_running", "port": self.trap_port}

        try:
            loop = asyncio.get_event_loop()
            self._trap_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._trap_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._trap_sock.bind(("0.0.0.0", self.trap_port))
            self._trap_sock.setblocking(False)

            self._trap_running = True
            self._trap_task = asyncio.create_task(self._trap_loop())
            logger.info(f"SNMP trap receiver started on UDP port {self.trap_port}")
            return {"status": "started", "port": self.trap_port}

        except Exception as e:
            logger.error(f"Failed to start SNMP trap receiver: {e}")
            return {"status": "error", "message": str(e)}

    async def _trap_loop(self):
        """Read UDP datagrams and parse as SNMP traps."""
        loop = asyncio.get_event_loop()
        while self._trap_running:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self._trap_sock, 65535),
                    timeout=1.0,
                )
                self._process_trap(data, addr[0])
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                if self._trap_running:
                    logger.debug(f"Trap recv error: {e}")

    def _process_trap(self, data: bytes, source_ip: str):
        """Parse minimal SNMP trap from raw bytes."""
        trap = {
            "timestamp": datetime.now().isoformat(),
            "source": source_ip,
            "oids": {},
            "raw_length": len(data),
        }

        # Best-effort OID extraction from BER-encoded SNMP
        try:
            import pyasn1.codec.der.decoder as decoder
            from pyasn1.type import univ
            msg, _ = decoder.decode(data, asn1Spec=univ.Sequence())
            if len(msg) >= 3:
                var_bind_list = msg[-1]
                if hasattr(var_bind_list, 'getComponentByPosition'):
                    for i in range(min(len(var_bind_list), 20)):
                        vb = var_bind_list.getComponentByPosition(i)
                        if vb and len(vb) >= 2:
                            oid = str(vb[0])
                            val = str(vb[1])
                            trap["oids"][oid] = val
        except Exception:
            pass

        self._traps.append(trap)
        logger.info(f"SNMP trap from {source_ip} ({len(data)} bytes)")

        if self._broadcast_fn:
            asyncio.create_task(self._broadcast_fn({
                "type": "snmp_trap",
                "trap": trap,
            }))

        # Persist to database
        try:
            from .nx_bridge import get_bridge
            asyncio.create_task(get_bridge().record_security_event(
                "snmp", "info", f"SNMP trap from {source_ip}",
                source=source_ip,
                details={"oids": trap.get("oids", {})}))
        except Exception:
            pass

    async def stop_trap_receiver(self) -> dict:
        if not self._trap_running:
            return {"status": "not_running"}

        self._trap_running = False
        if self._trap_task:
            self._trap_task.cancel()
            self._trap_task = None
        if self._trap_sock:
            self._trap_sock.close()
            self._trap_sock = None
        logger.info("SNMP trap receiver stopped")
        return {"status": "stopped"}

    def get_traps(self, limit: int = 50) -> list[dict]:
        return list(self._traps)[-limit:]

    def get_status(self) -> dict:
        return {
            "trap_receiver_running": self._trap_running,
            "trap_port": self.trap_port,
            "traps_stored": len(self._traps),
        }

    # ── Topology Discovery ──────────────────────────────────────────
    # OID constants for ARP and bridge tables
    _OID_ARP_TABLE = "1.3.6.1.2.1.4.22.1.2"           # ipNetToMediaPhysAddress
    _OID_BRIDGE_FDB = "1.3.6.1.2.1.17.4.3.1.2"        # dot1dTpFdbPort
    _OID_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.3.1.2"    # dot1dBasePortIfIndex
    _OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"             # ifDescr (for port names)

    async def discover_topology(self, switch_ip: str, community: str = "public",
                                version: str = "2c", port: int = 161) -> dict:
        """Discover device connections via SNMP by querying ARP and bridge tables.

        Walks three MIB tables on the target switch/router and merges them:
          1. ipNetToMediaPhysAddress (ARP table)  → IP ↔ MAC mapping
          2. dot1dTpFdbPort          (bridge FDB) → MAC ↔ bridge-port mapping
          3. dot1dBasePortIfIndex                 → bridge-port ↔ ifIndex mapping
          4. ifDescr                              → ifIndex ↔ port name (e.g. Gi0/1)

        Returns:
            {
                "switch_ip": "...",
                "devices": [{"mac": "...", "ip": "...", "port": "Gi0/1", "vlan": 1}, ...],
                "total": N,
                "status": "success" | "error" | "unavailable"
            }
        """
        result = {"switch_ip": switch_ip, "devices": [], "total": 0, "status": "error"}

        # ── Prefer pysnmp, fall back to subprocess snmpwalk ─────────
        if _check_pysnmp():
            try:
                result = await self._discover_pysnmp(switch_ip, community, version, port)
            except Exception as e:
                logger.error(f"pysnmp topology discovery failed for {switch_ip}: {e}")
                result["status"] = "error"
                result["message"] = str(e)
                return result
        else:
            # Try subprocess snmpwalk as fallback
            try:
                result = self._discover_subprocess(switch_ip, community, version, port)
            except FileNotFoundError:
                return {"status": "unavailable",
                        "message": "pysnmp not installed and snmpwalk not found on PATH",
                        "switch_ip": switch_ip, "devices": [], "total": 0}
            except subprocess.TimeoutExpired:
                result["status"] = "error"
                result["message"] = f"SNMP walk timed out for {switch_ip}"
                return result
            except Exception as e:
                logger.error(f"snmpwalk topology discovery failed for {switch_ip}: {e}")
                result["status"] = "error"
                result["message"] = str(e)
                return result

        # ── Persist to CurrentScan ──────────────────────────────────
        if result["status"] == "success" and result["devices"]:
            try:
                await self._write_topology_to_current_scan(switch_ip, result["devices"])
            except Exception as e:
                logger.warning(f"Failed to write topology to CurrentScan: {e}")

        return result

    # ── pysnmp implementation ───────────────────────────────────────

    async def _discover_pysnmp(self, switch_ip: str, community: str,
                               version: str, port: int) -> dict:
        from pysnmp.hlapi.v3arch.asyncio.cmdgen import (
            SnmpEngine, CommunityData, ContextData, ObjectType, walk_cmd,
        )
        from pysnmp.hlapi.v3arch.asyncio.transport import UdpTransportTarget
        from pysnmp.smi.rfc1902 import ObjectIdentity

        result = {"switch_ip": switch_ip, "devices": [], "total": 0, "status": "success"}
        engine = SnmpEngine()
        mp_model = 1 if version == "2c" else 0
        target = await UdpTransportTarget.create((switch_ip, port), timeout=5.0, retries=1)
        auth = CommunityData(community, mpModel=mp_model)
        ctx = ContextData()

        # 1) Walk ARP table: ipNetToMediaPhysAddress → IP → MAC (hex)
        arp_table: dict[str, str] = {}   # ip -> mac_normalized
        async for (err_ind, err_stat, _, var_bind_table) in walk_cmd(
            engine, auth, target, ctx,
            ObjectType(ObjectIdentity(self._OID_ARP_TABLE)),
        ):
            if err_ind or err_stat:
                break
            for vb in var_bind_table:
                oid_str = str(vb[0])
                # OID tail: ...ipNetToMediaPhysAddress.<ifIndex>.<a>.<b>.<c>.<d>
                parts = oid_str.split(".")
                if len(parts) >= 4:
                    ip_addr = ".".join(parts[-4:])
                    mac_hex = self._snmp_value_to_mac(vb[1])
                    if mac_hex:
                        arp_table[ip_addr] = mac_hex

        # 2) Walk bridge FDB: dot1dTpFdbAddress → MAC -> bridge port
        #    OID: dot1dTpFdbPort.<mac_as_oid_suffix>
        mac_to_bridge_port: dict[str, int] = {}  # mac_normalized -> bridge_port
        async for (err_ind, err_stat, _, var_bind_table) in walk_cmd(
            engine, auth, target, ctx,
            ObjectType(ObjectIdentity(self._OID_BRIDGE_FDB)),
        ):
            if err_ind or err_stat:
                break
            for vb in var_bind_table:
                oid_str = str(vb[0])
                mac_from_oid = self._oid_suffix_to_mac(oid_str)
                port_num = int(vb[1])
                if mac_from_oid and port_num > 0:
                    mac_to_bridge_port[mac_from_oid] = port_num

        # 3) Walk dot1dBasePortIfIndex: bridge_port -> ifIndex
        bridge_port_to_ifindex: dict[int, int] = {}
        async for (err_ind, err_stat, _, var_bind_table) in walk_cmd(
            engine, auth, target, ctx,
            ObjectType(ObjectIdentity(self._OID_PORT_IFINDEX)),
        ):
            if err_ind or err_stat:
                break
            for vb in var_bind_table:
                oid_str = str(vb[0])
                # last integer is the bridge port number
                bp = int(oid_str.split(".")[-1])
                ifindex = int(vb[1])
                bridge_port_to_ifindex[bp] = ifindex

        # 4) Walk ifDescr to get human-readable port names
        ifindex_to_name: dict[int, str] = {}
        async for (err_ind, err_stat, _, var_bind_table) in walk_cmd(
            engine, auth, target, ctx,
            ObjectType(ObjectIdentity(self._OID_IF_DESCR)),
        ):
            if err_ind or err_stat:
                break
            for vb in var_bind_table:
                oid_str = str(vb[0])
                ifindex = int(oid_str.split(".")[-1])
                ifindex_to_name[ifindex] = str(vb[1])

        # ── Merge into device list ──────────────────────────────────
        # Build reverse ARP: mac -> ip (first IP per MAC wins)
        mac_to_ip: dict[str, str] = {}
        for ip, mac in arp_table.items():
            mac_to_ip.setdefault(mac, ip)

        # Combine: MAC -> bridge_port -> ifIndex -> port_name
        for mac, bp in mac_to_bridge_port.items():
            ifindex = bridge_port_to_ifindex.get(bp)
            port_name = ifindex_to_name.get(ifindex, str(bp)) if ifindex else str(bp)
            ip_addr = mac_to_ip.get(mac, "")
            result["devices"].append({
                "mac": mac,
                "ip": ip_addr,
                "port": port_name,
                "vlan": 0,  # VLAN not available from standard MIB walk
            })

        result["total"] = len(result["devices"])
        if not result["devices"]:
            result["status"] = "success"
            result["message"] = "No devices discovered (empty ARP/bridge tables)"
        return result

    # ── subprocess snmpwalk fallback ────────────────────────────────

    def _discover_subprocess(self, switch_ip: str, community: str,
                             version: str, port: int) -> dict:
        result = {"switch_ip": switch_ip, "devices": [], "total": 0, "status": "success"}

        snmp_ver = "2c" if version == "2c" else "1"

        # 1) ARP table walk
        arp_raw = self._snmpwalk_cmd(
            switch_ip, community, snmp_ver, port, self._OID_ARP_TABLE)
        arp_table: dict[str, str] = {}   # ip -> mac_normalized
        for line in arp_raw:
            ip, mac = self._parse_arp_line(line)
            if ip and mac:
                arp_table[ip] = mac

        # 2) Bridge FDB walk
        fdb_raw = self._snmpwalk_cmd(
            switch_ip, community, snmp_ver, port, self._OID_BRIDGE_FDB)
        mac_to_bridge_port: dict[str, int] = {}
        for line in fdb_raw:
            mac, bp = self._parse_fdb_line(line)
            if mac and bp and bp > 0:
                mac_to_bridge_port[mac] = bp

        # 3) Bridge port → ifIndex mapping
        port_if_raw = self._snmpwalk_cmd(
            switch_ip, community, snmp_ver, port, self._OID_PORT_IFINDEX)
        bridge_port_to_ifindex: dict[int, int] = {}
        for line in port_if_raw:
            bp, ifindex = self._parse_port_ifindex_line(line)
            if bp is not None and ifindex is not None:
                bridge_port_to_ifindex[bp] = ifindex

        # 4) ifDescr walk for port names
        ifdescr_raw = self._snmpwalk_cmd(
            switch_ip, community, snmp_ver, port, self._OID_IF_DESCR)
        ifindex_to_name: dict[int, str] = {}
        for line in ifdescr_raw:
            ifindex, name = self._parse_ifdescr_line(line)
            if ifindex is not None and name:
                ifindex_to_name[ifindex] = name

        # ── Merge ───────────────────────────────────────────────────
        mac_to_ip: dict[str, str] = {}
        for ip, mac in arp_table.items():
            mac_to_ip.setdefault(mac, ip)

        for mac, bp in mac_to_bridge_port.items():
            ifindex = bridge_port_to_ifindex.get(bp)
            port_name = ifindex_to_name.get(ifindex, str(bp)) if ifindex else str(bp)
            ip_addr = mac_to_ip.get(mac, "")
            result["devices"].append({
                "mac": mac,
                "ip": ip_addr,
                "port": port_name,
                "vlan": 0,
            })

        result["total"] = len(result["devices"])
        if not result["devices"]:
            result["message"] = "No devices discovered (empty ARP/bridge tables)"
        return result

    # ── snmpwalk subprocess helper ──────────────────────────────────

    @staticmethod
    def _snmpwalk_cmd(target_ip: str, community: str, version: str,
                      port: int, oid: str) -> list[str]:
        """Run snmpwalk via subprocess and return output lines."""
        cmd = [
            "snmpwalk", "-v", version, "-c", community,
            f"{target_ip}:{port}", oid,
        ]
        output = subprocess.check_output(
            cmd, universal_newlines=True, stderr=subprocess.STDOUT, timeout=30)
        return [l for l in output.splitlines() if l.strip()]

    # ── Line parsers for subprocess output ───────────────────────────

    @staticmethod
    def _parse_arp_line(line: str) -> tuple[str, str]:
        """Parse a snmpwalk line from ipNetToMediaPhysAddress.

        Handles formats:
          ...ipNetToMediaPhysAddress.3.192.168.1.14 = STRING: 2c:f4:32:18:61:43
          ...ipNetToMediaPhysAddress.3.1.2.3.4 = Hex-STRING: 2C F4 32 18 61 43
          ipNetToMediaPhysAddress[3][192.168.1.9] 6C:6C:6C:6C:6C:b6
        """
        ip, mac = "", ""
        try:
            if "STRING:" in line and "=" in line:
                left, right = line.split("=", 1)
                mac_part = right.split("STRING:")[-1].strip()
                mac = SNMPService._normalize_mac_str(mac_part)
                oid_parts = left.strip().split(".")
                ip = ".".join(oid_parts[-4:])
            elif "Hex-STRING:" in line and "=" in line:
                left, right = line.split("=", 1)
                mac_part = right.split("Hex-STRING:")[-1].strip()
                # Hex-STRING format: "2C F4 32 18 61 43"
                mac = ":".join(p.lower() for p in mac_part.split())
                oid_parts = left.strip().split(".")
                ip = ".".join(oid_parts[-4:])
            elif line.startswith("ipNetToMediaPhysAddress"):
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].split("[")[-1].rstrip("]")
                    mac = SNMPService._normalize_mac_str(parts[1])
        except Exception:
            pass
        return ip, mac

    @staticmethod
    def _parse_fdb_line(line: str) -> tuple[str, int]:
        """Parse dot1dTpFdbPort line: ...dot1dTpFdbPort.x.x.x.x.x.x = INTEGER: 3"""
        mac, port_num = "", 0
        try:
            if "=" in line:
                left, right = line.split("=", 1)
                mac = SNMPService._oid_suffix_to_mac_str(left.strip())
                val_part = right.strip()
                if "INTEGER:" in val_part:
                    port_num = int(val_part.split("INTEGER:")[-1].strip())
        except Exception:
            pass
        return mac, port_num

    @staticmethod
    def _parse_port_ifindex_line(line: str) -> tuple[int | None, int | None]:
        """Parse dot1dBasePortIfIndex line: ...x = INTEGER: 3"""
        try:
            if "=" in line:
                left, right = line.split("=", 1)
                bp = int(left.strip().split(".")[-1])
                val = right.strip()
                if "INTEGER:" in val:
                    ifindex = int(val.split("INTEGER:")[-1].strip())
                    return bp, ifindex
        except Exception:
            pass
        return None, None

    @staticmethod
    def _parse_ifdescr_line(line: str) -> tuple[int | None, str]:
        """Parse ifDescr line: ...ifDescr.3 = STRING: "GigabitEthernet0/1\""""
        try:
            if "=" in line:
                left, right = line.split("=", 1)
                ifindex = int(left.strip().split(".")[-1])
                name = right.strip()
                if "STRING:" in name:
                    name = name.split("STRING:")[-1].strip().strip('"')
                return ifindex, name
        except Exception:
            pass
        return None, ""

    # ── MAC address conversion helpers ───────────────────────────────

    @staticmethod
    def _snmp_value_to_mac(value) -> str | None:
        """Convert pysnmp OctetString to xx:xx:xx:xx:xx:xx MAC format."""
        try:
            raw = bytes(value)
            if len(raw) == 6:
                return ":".join(f"{b:02x}" for b in raw)
        except Exception:
            pass
        return None

    @staticmethod
    def _oid_suffix_to_mac(oid_str: str) -> str | None:
        """Extract MAC from pysnmp OID like ...1.3.6.1.2.1.17.4.3.1.1.0.60.52.18.1.23"""
        parts = oid_str.split(".")
        if len(parts) >= 6:
            mac_parts = parts[-6:]
            try:
                nums = [int(p) for p in mac_parts]
                if all(0 <= n <= 255 for n in nums):
                    return ":".join(f"{n:02x}" for n in nums)
            except ValueError:
                pass
        return None

    @staticmethod
    def _oid_suffix_to_mac_str(oid_str: str) -> str:
        """Extract MAC from string OID suffix (subprocess output)."""
        parts = oid_str.split(".")
        if len(parts) >= 6:
            try:
                nums = [int(p) for p in parts[-6:]]
                return ":".join(f"{n:02x}" for n in nums)
            except ValueError:
                pass
        return ""

    @staticmethod
    def _normalize_mac_str(mac: str) -> str:
        """Normalize any MAC format to xx:xx:xx:xx:xx:xx."""
        cleaned = re.sub(r"[^a-fA-F0-9]", "", mac)
        if len(cleaned) == 12:
            return ":".join(cleaned[i:i+2].lower() for i in range(0, 12, 2))
        return mac.lower()

    # ── Persist topology to CurrentScan ─────────────────────────────

    async def _write_topology_to_current_scan(self, switch_ip: str, devices: list[dict]):
        """Write discovered topology relationships into the CurrentScan table."""
        from server.db.compat import get_temp_db_connection
        conn = get_temp_db_connection()
        try:
            for d in devices:
                conn.execute(
                    """UPDATE CurrentScan SET scanParentMAC = ?, scanParentPort = ?
                       WHERE scanMac = ?""",
                    (switch_ip.lower(), d.get("port", ""), d["mac"].lower()),
                )
            conn.commit()
            logger.info(f"Wrote {len(devices)} topology entries to CurrentScan for {switch_ip}")
        finally:
            conn.close()


_service: Optional[SNMPService] = None


def get_snmp_service() -> SNMPService:
    global _service
    if _service is None:
        _service = SNMPService()
    return _service
