"""SNMP service for CyberClaw — device info queries and trap reception.

Uses pysnmp v7 (pure Python, no system dependencies).
- get_device_info(): query sysDescr, sysName, ifTable via SNMP GET/WALK
- Trap receiver: listens on non-privileged port 1162
"""
import asyncio
import logging
import socket
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


_service: Optional[SNMPService] = None


def get_snmp_service() -> SNMPService:
    global _service
    if _service is None:
        _service = SNMPService()
    return _service
