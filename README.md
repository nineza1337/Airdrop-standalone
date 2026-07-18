# AirDrop Standalone

Standalone AirDrop CLI for Linux (Kali) over **AWDL** — discover receivers, send Ask popups, upload files, flood, and capture traffic.

> **Disclaimer / คำเตือน**  
> For authorized security research and education only. Use only on networks and devices you own or have explicit permission to test. Misuse may violate law and Apple terms of service.

---

## English

### Features

| Command | Description |
|---------|-------------|
| `find` | BLE wake + mDNS discovery loop; saves `discover.last.json` |
| `flood` | Repeated Ask popups to one or all AWDL neighbors |
| `ask` | Single Ask popup (file metadata or URL) |
| `send` | Ask + file upload (modern iOS: TLS /Ask → companion-link + asquic) |
| `sniff` | Live capture to/from a target IPv6 (pcap export) |
| `neigh` | List AWDL link-local neighbors |

### Requirements

- **Linux** with root (`sudo`)
- **Kali** (or similar) with AWDL support:
  - [`owl`](https://github.com/seemoo-lab/owl) — AWDL userspace
  - Monitor-mode Wi‑Fi (`airmon-ng`) or compatible adapter
- **Python 3.10+**
- **System**: `bluez` (`hcitool`, `hciconfig`) for optional BLE wake
- **Optional**: `tcpdump`, `openssl`, `libarchive` (for legacy TLS upload)

```bash
pip install -r requirements.txt
# legacy TLS file upload also needs:
pip install libarchive-c
```

### Quick start

**Terminal 1 — AWDL interface**

```bash
sudo airmon-ng check kill && sudo airmon-ng start wlan0
sudo owl -i wlan0mon -N
```

**Terminal 2 — tool (as root)**

```bash
sudo python3 main.py find                    # Ctrl+C to save devices
sudo python3 main.py find --once --duration 20
sudo python3 main.py send --target fe80::xxxx:xxxx:xxxx:xxxx -f poke.txt
sudo python3 main.py ask   --target fe80::xxxx:xxxx:xxxx:xxxx -n "Lab"
sudo python3 main.py flood --target fe80::xxxx:xxxx:xxxx:xxxx
sudo python3 main.py sniff --target fe80::xxxx:xxxx:xxxx:xxxx -w capture.pcap
```

On the **receiver** (iPhone/iPad): AirDrop → **Everyone**, share sheet open, screen unlocked.

### TLS keys

On first run, the tool creates `./keys/` and either copies from `../opendrop/keys` or generates a self-signed cert. See `keys/README.md`. **Never commit `key.pem` to a public repo.**

### Module layout

```
main.py          CLI entry
config.py        paths, logging, TLS keys
constants.py     PCAP-derived packet templates
netutil.py       IPv6 / socket helpers
peers.py         data models
ble.py           BLE AirDrop wake beacon
discovery.py     mDNS + TLS /Discover
modern.py        companion-link + asquic
legacy.py        TLS :8770 (OpenDrop-style)
actions.py       routing + flood
fastnet.py       concurrent probes + fast flood
sniffer.py       pcap capture
asquic_client.py aioquic upload client
quic_profile.py  QUIC profile helpers
decode.py        offline pcap decoder
```

### Privacy / redaction (this public copy)

Lab-capture identifiers in `constants.py`, `netutil.py`, `main.py`, and `quic_profile.py` were replaced with `xxxx` placeholders (device name, service UUID, auth token, MAC, IPv6). Comments in code mark each redaction. Replace `--target` with addresses from your own `find` output.

### Debug

```bash
sudo python3 main.py find --dbg
sudo python3 main.py send --target fe80::... -f poke.txt --dbg
```

---

## ภาษาไทย

### คุณสมบัติ

| คำสั่ง | คำอธิบาย |
|--------|----------|
| `find` | ปลุก BLE + สแกน mDNS วนจนกว่ากด Ctrl+C แล้วบันทึก `discover.last.json` |
| `flood` | ส่งป๊อปอัป Ask ซ้ำๆ ไปยังเป้าหมายหรือเพื่อนบ้าน AWDL ทั้งหมด |
| `ask` | ส่ง Ask ครั้งเดียว (ไฟล์หรือ URL) |
| `send` | ส่งไฟล์จริง (iOS ใหม่: TLS /Ask แล้ว companion-link + asquic) |
| `sniff` | จับแพ็กเก็ตไป/กลับ IPv6 เป้าหมาย (บันทึก .pcap) |
| `neigh` | แสดงเพื่อนบ้าน link-local บน awdl0 |

### สิ่งที่ต้องมี

- **Linux** และรันด้วย root (`sudo`)
- **Kali** (หรือเทียบเท่า) พร้อม AWDL:
  - [`owl`](https://github.com/seemoo-lab/owl)
  - การ์ด Wi‑Fi โหมด monitor (`airmon-ng`)
- **Python 3.10+**
- **ระบบ**: `bluez` สำหรับ BLE wake (ถ้าใช้)
- **เสริม**: `tcpdump`, `openssl`, `libarchive` (อัปโหลดแบบ TLS เก่า)

```bash
pip install -r requirements.txt
pip install libarchive-c   # สำหรับ /Upload แบบ legacy
```

### เริ่มใช้งาน

**เทอร์มินัล 1 — เปิด AWDL**

```bash
sudo airmon-ng check kill && sudo airmon-ng start wlan0
sudo owl -i wlan0mon -N
```

**เทอร์มินัล 2 — รันเครื่องมือ**

```bash
sudo python3 main.py find
sudo python3 main.py send --target fe80::xxxx:xxxx:xxxx:xxxx -f poke.txt
```

บน **เครื่องรับ** (iPhone/iPad): ตั้ง AirDrop เป็น **ทุกคน (Everyone)** เปิดแผงแชร์ ปลดล็อกหน้าจอ

### คีย์ TLS

โฟลเดอร์ `keys/` จะถูกสร้างอัตโนมัติ อ่านรายละเอียดใน `keys/README.md` **ห้ามอัปโหลด `key.pem` ขึ้น GitHub**

### การลบข้อมูลส่วนตัว (เวอร์ชัน public)

ไฟล์จาก lab capture ถูกแทนที่ด้วย `xxxx` แล้ว (ชื่อเครื่อง, UUID บริการ, auth token, MAC, IPv6) มีคอมเมนต์ในโค้ดบอกจุดที่ redact ใช้ IPv6 จากผล `find` ของคุณเองแทน `--target` ตัวอย่าง

### โหมดดีบัก

```bash
sudo python3 main.py find --dbg
```

---

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

Copyright (C) 2026 [nineza1337](https://github.com/nineza1337)

For authorized security research and education only. See the disclaimer at the top of this README.
