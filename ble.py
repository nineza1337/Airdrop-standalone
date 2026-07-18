"""BLE wake beacon (airdrop-wake.sh — iOS 26 AirDrop Continuity type 0x05)."""

from __future__ import annotations

import secrets
import shutil
import subprocess
import threading
import time

from config import log


class BleWakeBeacon:
    """Broadcast AirDrop BLE advertisement via hcitool (wake AWDL on nearby iOS)."""

    def __init__(self, hci: str = "hci0"):
        self.hci = hci
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stopped_bt = False
        self._ready = threading.Event()

    @staticmethod
    def _split_hex(*tokens: str) -> list[str]:
        out: list[str] = []
        for tok in tokens:
            tok = tok.replace("0x", "").replace(" ", "").upper()
            if len(tok) > 2:
                out.extend(tok[i : i + 2] for i in range(0, len(tok), 2))
            elif tok:
                out.append(tok.zfill(2))
        return out

    def _hci_cmd(self, label: str, ogf: str, ocf: str, *hex_tokens: str) -> int | None:
        """Run hcitool HCI command; return status byte (0=OK) or None."""
        byte_args = self._split_hex(*hex_tokens)
        args = ["hcitool", "-i", self.hci, "cmd", ogf, ocf, *byte_args]
        log(f"BLE {label}: {' '.join(args)}", level="dbg")
        try:
            out = subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, timeout=5)
            log(f"BLE {label} response:\n{out}", level="dbg")
            status = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("01 ") and len(line.split()) >= 4:
                    status = int(line.split()[-1], 16)
            if status is not None and status != 0:
                names = {0x0C: "Command Disallowed (stop bluetoothd?)", 0x01: "Unknown Command"}
                log(f"BLE {label} HCI status 0x{status:02X} {names.get(status, '')}", level="warn")
            return status
        except (OSError, subprocess.SubprocessError) as exc:
            log(f"BLE {label} failed: {exc}", level="warn")
            return None

    def _build_beacon_hex(self) -> list[str]:
        p4 = secrets.token_hex(4).upper()
        h8 = secrets.token_hex(8).upper()
        log(f"BLE beacon prefix={p4} hash={h8} version=03", level="dbg")
        raw = f"1B02011A17FF4C000512{p4}0000000003{h8}0000000000"
        return self._split_hex(raw)

    def _prepare_adapter(self) -> None:
        if shutil.which("hcitool") is None:
            log("hcitool not found — apt install bluez", level="warn")
            return
        if shutil.which("systemctl"):
            try:
                active = subprocess.run(
                    ["systemctl", "is-active", "bluetooth"],
                    capture_output=True, text=True, timeout=3,
                )
                if active.stdout.strip() == "active":
                    log("stopping bluetoothd for raw HCI advertising", level="dbg")
                    subprocess.run(["systemctl", "stop", "bluetooth"], timeout=5)
                    self._stopped_bt = True
                    time.sleep(0.5)
            except (OSError, subprocess.SubprocessError):
                pass
        if shutil.which("hciconfig"):
            subprocess.run(["hciconfig", self.hci, "down"], capture_output=True, timeout=3)
            time.sleep(0.3)
            subprocess.run(["hciconfig", self.hci, "up"], capture_output=True, timeout=3)
            time.sleep(0.3)
        self._hci_cmd("HCI_Reset", "0x03", "0x0003")
        time.sleep(0.3)
        subprocess.run(["hciconfig", self.hci, "up"], capture_output=True, timeout=3)

    def _enable_beacon(self) -> bool:
        st = self._hci_cmd(
            "LE_Set_Advertising_Parameters", "0x08", "0x0006",
            "A0", "00", "A0", "00", "00", "00", "00", "00", "00", "00", "00", "00", "07", "00",
        )
        if st == 0x0C:
            return False
        st = self._hci_cmd("LE_Set_Advertising_Data", "0x08", "0x0008", *self._build_beacon_hex())
        if st == 0x0C:
            return False
        st = self._hci_cmd("LE_Set_Advertise_Enable(ON)", "0x08", "0x000A", "01")
        return st != 0x0C

    def _disable_beacon(self) -> None:
        self._hci_cmd("LE_Set_Advertise_Enable(OFF)", "0x08", "0x000A", "00")
        if self._stopped_bt and shutil.which("systemctl"):
            subprocess.run(["systemctl", "start", "bluetooth"], capture_output=True, timeout=5)

    def _loop(self, refresh_s: float) -> None:
        try:
            self._prepare_adapter()
            if self._enable_beacon():
                log(f"BLE AirDrop wake beacon ON ({self.hci})")
            else:
                log(
                    f"BLE advertising blocked on {self.hci} — try: sudo systemctl stop bluetooth",
                    level="warn",
                )
            getattr(self, "_ready", threading.Event()).set()
            count = 0
            while not self._stop.wait(refresh_s):
                count += 1
                log(f"BLE refresh #{count}", level="dbg")
                self._hci_cmd("LE_Set_Advertising_Data", "0x08", "0x0008", *self._build_beacon_hex())
        except Exception as exc:
            log(f"BLE wake thread: {exc}", level="warn")
        finally:
            self._ready.set()
            self._disable_beacon()

    def start(self, refresh_s: float = 15.0) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._loop, args=(refresh_s,), daemon=True)
        self._thread.start()

    def wait_ready(self, timeout: float = 8.0) -> bool:
        """Wait until first beacon TX attempt (or timeout)."""
        ev = getattr(self, "_ready", None)
        if ev is None:
            return False
        return ev.wait(timeout)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


def brief_ble_wake(hci: str, seconds: float = 5.0) -> None:
    """Short BLE burst to wake AWDL on nearby iOS before send/ask."""
    beacon = BleWakeBeacon(hci)
    try:
        beacon.start()
        if not beacon.wait_ready(timeout=8.0):
            log("BLE wake slow — waiting up to 5s more", level="dbg")
            beacon.wait_ready(timeout=5.0)
        log(f"BLE wake active {seconds}s", level="dbg")
        time.sleep(seconds)
    finally:
        beacon.stop()
