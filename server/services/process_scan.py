"""CyberClaw scan processing pipeline

Full pipeline from raw scan results to device/event records.
Ported from NetAlertX session_events.py + device_handling.py, adapted
for CyberClaw's async architecture and simpler schema.

Pipeline stages:
  populate_current_scan  ->  process_scan_results
                               1. create_new_devices
                               2. update_devices_from_scan
                               3. update_presence
                               4. update_icons_and_types
                               5. insert_scan_events
                               6. clear_current_scan
"""

import asyncio
import logging

from server.db.compat import (
    get_temp_db_connection,
    timeNowUTC,
    mylog,
    normalize_mac,
    NULL_EQUIVALENTS,
    NULL_EQUIVALENTS_SQL,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stage 0: Populate CurrentScan temp table
# ---------------------------------------------------------------------------

def _sync_populate_current_scan(results: list[dict], source: str = "SCAN"):
    """Write scan results into CurrentScan temp table.

    Each result dict should contain: ip, mac, vendor, method.
    Additional keys (name, parent_mac, parent_port, site, type) are optional.
    """
    conn = get_temp_db_connection()
    try:
        # Clear previous scan data
        conn.execute("DELETE FROM CurrentScan")

        for r in results:
            mac = normalize_mac(r.get("mac", ""))
            if not mac or len(mac) != 12:
                continue
            # Format MAC as xx:xx:xx:xx:xx:xx for storage
            mac_fmt = ":".join(mac[i:i+2] for i in range(0, 12, 2))

            ip = r.get("ip", "")
            vendor = r.get("vendor", "")
            method = r.get("method", source)
            name = r.get("name", "")
            parent_mac = r.get("parent_mac", "")
            parent_port = r.get("parent_port", "")
            site = r.get("site", "")
            dev_type = r.get("type", "")

            conn.execute(
                """INSERT OR IGNORE INTO CurrentScan
                   (scanMac, scanLastIP, scanVendor, scanSourcePlugin,
                    scanName, scanParentMAC, scanParentPort, scanSite, scanType)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (mac_fmt, ip, vendor, method,
                 name, parent_mac, parent_port, site, dev_type),
            )
        conn.commit()
        mylog("debug", f"[ProcessScan] populate_current_scan: {len(results)} results written")
    except Exception as e:
        logger.error(f"populate_current_scan error: {e}")
    finally:
        conn.close()


async def populate_current_scan(results: list[dict], source: str = "SCAN"):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None, lambda: _sync_populate_current_scan(results, source)
    )


# ---------------------------------------------------------------------------
# Stage 1: Create new devices
# ---------------------------------------------------------------------------

def _sync_create_new_devices() -> list[dict]:
    """Find MACs in CurrentScan not yet in Devices, insert them.

    Returns list of event dicts for new-device events.
    """
    events = []
    conn = get_temp_db_connection()
    try:
        now = timeNowUTC()

        # Find scan rows whose MAC is not in Devices
        rows = conn.execute("""
            SELECT cs.scanMac, cs.scanLastIP, cs.scanVendor,
                   cs.scanSourcePlugin, cs.scanName, cs.scanType
            FROM CurrentScan cs
            WHERE NOT EXISTS (
                SELECT 1 FROM Devices d WHERE d.devMac = cs.scanMac
            )
        """).fetchall()

        for row in rows:
            mac = row["scanMac"]
            ip = row["scanLastIP"] or ""
            vendor = row["scanVendor"] or ""
            source_plugin = row["scanSourcePlugin"] or "SCAN"
            name = row["scanName"] or ""
            scan_type = row["scanType"] or ""

            # Infer device type/icon via heuristics
            dev_type = scan_type or "unknown"
            dev_icon = ""
            try:
                from server.db.scan.device_heuristics import guess_device_attributes
                icon, type_ = guess_device_attributes(
                    vendor, mac, ip, name, "", "unknown"
                )
                if type_ and type_ != "unknown":
                    dev_type = type_
                if icon:
                    dev_icon = icon
            except Exception:
                pass

            # Insert new device
            conn.execute(
                """INSERT OR IGNORE INTO Devices
                   (devMac, devName, devVendor, devLastIP, devType, devIcon,
                    devStatus, devDiscoveryMethod, devSourcePlugin,
                    devPresentLastScan, devIsNew, devIsArchived, devAlertDown,
                    devFirstConnection, devLastConnection)
                   VALUES (?, ?, ?, ?, ?, ?, 'secure', ?, ?, 1, 1, 0, 1, ?, ?)""",
                (mac, name or "(unknown)", vendor, ip, dev_type, dev_icon,
                 source_plugin, source_plugin, now, now),
            )

            # Insert "New Device" event
            conn.execute(
                """INSERT OR IGNORE INTO Events
                   (eveMac, eveIp, eveDateTime, eveEventType, eveAdditionalInfo, evePendingAlertEmail)
                   VALUES (?, ?, ?, 'New Device', ?, 1)""",
                (mac, ip, now, f"Discovered via {source_plugin}"),
            )

            events.append({
                "mac": mac,
                "ip": ip,
                "type": "New Device",
                "details": f"Discovered via {source_plugin}",
                "timestamp": now,
            })

            # Also record as a security event
            try:
                import json
                conn.execute(
                    """INSERT INTO security_events
                       (source_type, severity, message, target_mac, details, fsm_state)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    ("scan", "info", f"New device discovered: {mac}",
                     mac, json.dumps({"ip": ip, "vendor": vendor}), "secure"),
                )
            except Exception:
                pass

        conn.commit()
        mylog("debug", f"[ProcessScan] create_new_devices: {len(rows)} new devices")
    except Exception as e:
        logger.error(f"create_new_devices error: {e}")
    finally:
        conn.close()
    return events


async def create_new_devices() -> list[dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_create_new_devices)


# ---------------------------------------------------------------------------
# Stage 2: Update known devices from scan data
# ---------------------------------------------------------------------------

def _sync_update_devices_from_scan() -> list[dict]:
    """Update existing devices with data from CurrentScan.

    Tracks IP changes and returns event dicts for "IP Changed" events.
    """
    events = []
    conn = get_temp_db_connection()
    try:
        now = timeNowUTC()

        # Find devices that exist in both CurrentScan and Devices
        rows = conn.execute("""
            SELECT cs.scanMac, cs.scanLastIP, cs.scanVendor, cs.scanSourcePlugin,
                   d.devLastIP, d.devVendor
            FROM CurrentScan cs
            INNER JOIN Devices d ON d.devMac = cs.scanMac
        """).fetchall()

        for row in rows:
            mac = row["scanMac"]
            new_ip = row["scanLastIP"] or ""
            new_vendor = row["scanVendor"] or ""
            source_plugin = row["scanSourcePlugin"] or "SCAN"
            old_ip = row["devLastIP"] or ""

            # Build update sets for non-empty fields
            updates = ["devPresentLastScan = 1"]
            params: list = []

            if new_ip and new_ip not in NULL_EQUIVALENTS:
                updates.append("devLastIP = ?")
                params.append(new_ip)
                updates.append("devLastIPSource = ?")
                params.append(source_plugin)

            if new_vendor and new_vendor not in NULL_EQUIVALENTS:
                updates.append("devVendor = ?")
                params.append(new_vendor)
                updates.append("devVendorSource = ?")
                params.append(source_plugin)

            # Update last connection time
            updates.append("devLastConnection = ?")
            params.append(now)

            params.append(mac)
            conn.execute(
                f"UPDATE Devices SET {', '.join(updates)} WHERE devMac = ?",
                params,
            )

            # Detect IP change
            if (new_ip and old_ip
                    and new_ip not in NULL_EQUIVALENTS
                    and old_ip not in NULL_EQUIVALENTS
                    and new_ip != old_ip):
                conn.execute(
                    """INSERT OR IGNORE INTO Events
                       (eveMac, eveIp, eveDateTime, eveEventType, eveAdditionalInfo, evePendingAlertEmail)
                       VALUES (?, ?, ?, 'IP Changed', ?, 1)""",
                    (mac, new_ip, now, f"Previous IP: {old_ip}"),
                )
                events.append({
                    "mac": mac,
                    "ip": new_ip,
                    "type": "IP Changed",
                    "details": f"Previous IP: {old_ip}",
                    "timestamp": now,
                })

        conn.commit()
        mylog("debug", f"[ProcessScan] update_devices_from_scan: {len(rows)} devices updated, "
                        f"{len(events)} IP changes")
    except Exception as e:
        logger.error(f"update_devices_from_scan error: {e}")
    finally:
        conn.close()
    return events


async def update_devices_from_scan() -> list[dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_update_devices_from_scan)


# ---------------------------------------------------------------------------
# Stage 3: Update presence (online / offline)
# ---------------------------------------------------------------------------

def _sync_update_presence() -> list[dict]:
    """Set devPresentLastScan based on CurrentScan membership.

    Devices in CurrentScan -> present=1.
    Devices NOT in CurrentScan (previously present) -> present=0 + "Device Down" event.
    Devices NOT in CurrentScan (previously absent, now in CurrentScan) -> present=1 + "Connected" event.
    """
    events = []
    conn = get_temp_db_connection()
    try:
        now = timeNowUTC()

        # Mark devices seen in CurrentScan as present
        conn.execute("""
            UPDATE Devices SET devPresentLastScan = 1
            WHERE EXISTS (
                SELECT 1 FROM CurrentScan cs WHERE cs.scanMac = Devices.devMac
            )
        """)

        # Find devices going DOWN (were present, not in current scan)
        down_rows = conn.execute("""
            SELECT devMac, devLastIP
            FROM Devices
            WHERE devPresentLastScan = 1
              AND NOT EXISTS (
                  SELECT 1 FROM CurrentScan cs WHERE cs.scanMac = Devices.devMac
              )
        """).fetchall()

        for row in down_rows:
            mac = row["devMac"]
            ip = row["devLastIP"] or ""
            conn.execute(
                """INSERT OR IGNORE INTO Events
                   (eveMac, eveIp, eveDateTime, eveEventType, eveAdditionalInfo, evePendingAlertEmail)
                   VALUES (?, ?, ?, 'Device Down', '', 1)""",
                (mac, ip, now),
            )
            events.append({
                "mac": mac,
                "ip": ip,
                "type": "Device Down",
                "details": "",
                "timestamp": now,
            })

        # Now mark them as absent
        conn.execute("""
            UPDATE Devices SET devPresentLastScan = 0
            WHERE NOT EXISTS (
                SELECT 1 FROM CurrentScan cs WHERE cs.scanMac = Devices.devMac
            )
        """)

        # Find devices coming BACK (were absent, now in current scan)
        # We use the events table to detect reconnections
        reconnect_rows = conn.execute("""
            SELECT cs.scanMac, cs.scanLastIP
            FROM CurrentScan cs
            INNER JOIN Devices d ON d.devMac = cs.scanMac
            WHERE d.devPresentLastScan = 0
              OR d.devPresentLastScan IS NULL
        """).fetchall()

        for row in reconnect_rows:
            mac = row["scanMac"]
            ip = row["scanLastIP"] or ""

            # Check if there's a prior "Device Down" event -> "Down Reconnected"
            last_event = conn.execute(
                """SELECT eveEventType FROM Events
                   WHERE eveMac = ? ORDER BY eveDateTime DESC LIMIT 1""",
                (mac,),
            ).fetchone()

            event_type = "Connected"
            if last_event and last_event["eveEventType"] == "Device Down":
                event_type = "Down Reconnected"

            conn.execute(
                """INSERT OR IGNORE INTO Events
                   (eveMac, eveIp, eveDateTime, eveEventType, eveAdditionalInfo, evePendingAlertEmail)
                   VALUES (?, ?, ?, ?, '', 1)""",
                (mac, ip, now, event_type),
            )
            events.append({
                "mac": mac,
                "ip": ip,
                "type": event_type,
                "details": "",
                "timestamp": now,
            })

        conn.commit()
        mylog("debug", f"[ProcessScan] update_presence: {len(down_rows)} down, "
                        f"{len(reconnect_rows)} reconnected, {len(events)} events")
    except Exception as e:
        logger.error(f"update_presence error: {e}")
    finally:
        conn.close()
    return events


async def update_presence() -> list[dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_update_presence)


# ---------------------------------------------------------------------------
# Stage 4: Update device types and icons via heuristics
# ---------------------------------------------------------------------------

def _sync_update_icons_and_types():
    """For devices with empty devType/devIcon, infer via heuristics."""
    conn = get_temp_db_connection()
    try:
        # Find devices with empty or null devType
        type_rows = conn.execute(f"""
            SELECT devMac, devVendor, devLastIP, devName
            FROM Devices
            WHERE COALESCE(devType, '') IN ({NULL_EQUIVALENTS_SQL})
               OR devType IS NULL
        """).fetchall()

        type_updates = []
        icon_updates = []

        for row in type_rows:
            mac = row["devMac"]
            vendor = row["devVendor"] or ""
            ip = row["devLastIP"] or ""
            name = row["devName"] or ""

            try:
                from server.db.scan.device_heuristics import guess_device_attributes
                icon, type_ = guess_device_attributes(vendor, mac, ip, name, "", "unknown")
                if type_ and type_ != "unknown":
                    type_updates.append((type_, mac))
                if icon:
                    icon_updates.append((icon, mac))
            except Exception:
                pass

        if type_updates:
            conn.executemany(
                "UPDATE Devices SET devType = ? WHERE devMac = ?",
                type_updates,
            )
        if icon_updates:
            conn.executemany(
                "UPDATE Devices SET devIcon = ? WHERE devMac = ?",
                icon_updates,
            )

        conn.commit()
        mylog("debug", f"[ProcessScan] update_icons_and_types: "
                        f"{len(type_updates)} types, {len(icon_updates)} icons")
    except Exception as e:
        logger.error(f"update_icons_and_types error: {e}")
    finally:
        conn.close()


async def update_icons_and_types():
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _sync_update_icons_and_types)


# ---------------------------------------------------------------------------
# Stage 5: Collect and return all scan events (already inserted above)
# ---------------------------------------------------------------------------

def _sync_insert_scan_events() -> list[dict]:
    """Gather recent events generated during this scan cycle.

    Events are already inserted by stages 1-3. This function queries
    them back for broadcasting purposes.
    """
    events = []
    conn = get_temp_db_connection()
    try:
        # Get events from the last minute (this scan cycle)
        rows = conn.execute("""
            SELECT eveMac, eveIp, eveDateTime, eveEventType, eveAdditionalInfo
            FROM Events
            WHERE eveDateTime >= datetime('now', '-1 minute')
            ORDER BY eveDateTime DESC
        """).fetchall()

        for row in rows:
            events.append({
                "mac": row["eveMac"],
                "ip": row["eveIp"],
                "type": row["eveEventType"],
                "details": row["eveAdditionalInfo"] or "",
                "timestamp": row["eveDateTime"],
            })
    except Exception as e:
        logger.error(f"insert_scan_events error: {e}")
    finally:
        conn.close()
    return events


async def insert_scan_events() -> list[dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_insert_scan_events)


# ---------------------------------------------------------------------------
# Stage 6: Clear CurrentScan temp table
# ---------------------------------------------------------------------------

def _sync_clear_current_scan():
    conn = get_temp_db_connection()
    try:
        conn.execute("DELETE FROM CurrentScan")
        conn.commit()
        mylog("debug", "[ProcessScan] clear_current_scan: done")
    except Exception as e:
        logger.error(f"clear_current_scan error: {e}")
    finally:
        conn.close()


async def clear_current_scan():
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _sync_clear_current_scan)


# ===========================================================================
# Public API: Full pipeline
# ===========================================================================

async def process_scan_results() -> list[dict]:
    """Execute the complete scan processing pipeline.

    Returns a list of event dicts generated during processing,
    suitable for WebSocket broadcast.
    """
    all_events: list[dict] = []

    # Stage 1: New devices
    new_events = await create_new_devices()
    all_events.extend(new_events)

    # Stage 2: Update existing devices
    update_events = await update_devices_from_scan()
    all_events.extend(update_events)

    # Stage 3: Update presence (online/offline)
    presence_events = await update_presence()
    all_events.extend(presence_events)

    # Stage 4: Infer types/icons
    await update_icons_and_types()

    # Stage 5: Collect events for broadcast
    scan_events = await insert_scan_events()
    # (already captured above, but scan_events may include extras)

    # Stage 6: Clear temp table
    await clear_current_scan()

    mylog("info", f"[ProcessScan] Pipeline complete: {len(all_events)} events generated")
    return all_events


# Sync wrapper for callers that need it
def process_scan_results_sync() -> list[dict]:
    """Synchronous version of the full pipeline."""
    conn = get_temp_db_connection()
    conn.close()  # just validating DB works; real work uses own connections

    all_events: list[dict] = []

    all_events.extend(_sync_create_new_devices())
    all_events.extend(_sync_update_devices_from_scan())
    all_events.extend(_sync_update_presence())
    _sync_update_icons_and_types()
    all_events.extend(_sync_insert_scan_events())
    _sync_clear_current_scan()

    mylog("info", f"[ProcessScan] Pipeline (sync) complete: {len(all_events)} events")
    return all_events
