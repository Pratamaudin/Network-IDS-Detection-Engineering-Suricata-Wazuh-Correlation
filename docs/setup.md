# Setup — membangun sensor Suricata & integrasi Wazuh

Langkah membangun kembali modul ini di lab VirtualBox. Semua IP mengacu ke
jaringan host-only `192.168.56.0/24`.

## 1. VM sensor

- Ubuntu Server 22.04 LTS (headless, minimal install, OpenSSH aktif)
- RAM 2 GB, disk ~20 GB (dynamically allocated)
- **2 adapter jaringan:**
  - Adapter 1 — **Host-Only** (vboxnet lab). Advanced → **Promiscuous Mode: Allow All** (wajib — tanpa ini sensor tidak melihat trafik Kali↔DC01)
  - Adapter 2 — **NAT** (untuk update & download ruleset)

### IP statis host-only (netplan)

`/etc/netplan/00-installer-config.yaml` — sesuaikan nama interface (`ip a`):

```yaml
network:
  version: 2
  ethernets:
    enp0s3:            # NAT
      dhcp4: yes
    enp0s8:            # host-only
      dhcp4: no
      addresses: [192.168.56.50/24]
```

```bash
sudo netplan apply
sudo chmod 600 /etc/netplan/00-installer-config.yaml
# verifikasi
ping -c3 192.168.56.10    # DC01
ping -c3 8.8.8.8          # internet via NAT
```

Kelola sensor via SSH dari laptop (`ssh udin@192.168.56.50`) — copy-paste
tidak jalan di konsol VM headless.

## 2. Install Suricata + ruleset

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install suricata -y
sudo suricata-update          # ET Open ruleset
```

Edit `/etc/suricata/suricata.yaml` — lihat `suricata.yaml.snippet`:
- `HOME_NET: "[192.168.56.0/24]"`
- `af-packet` → `interface: enp0s8`
- `rule-files:` tambahkan `- local.rules`

Pasang custom rule ke `/var/lib/suricata/rules/local.rules`
(lihat `suricata-rules/local.rules`).

Validasi + jalankan:
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable --now suricata
```

> **Penting:** jika service "active" tapi 0 alert, ganti
> `/lib/systemd/system/suricata.service` dengan versi di
> `suricata-rules/suricata.service` (root + `-i enp0s8` + sandbox dimatikan),
> lalu `sudo systemctl daemon-reload && sudo systemctl restart suricata`.

### Tes capture

```bash
# dari Kali:
sudo nmap -sS -p 1-1000 192.168.56.10
# di sensor (baca file, bukan tail -f):
sudo grep -c "CUSTOM SCAN" /var/log/suricata/eve.json
```

## 3. Integrasi Wazuh

Install Wazuh agent di sensor, arahkan ke manager `192.168.56.30`:

```bash
sudo WAZUH_MANAGER="192.168.56.30" WAZUH_AGENT_NAME="suricata-sensor" apt install wazuh-agent -y
```

Tambahkan `<localfile>` ke `/var/ossec/etc/ossec.conf`
(lihat `wazuh-rules/agent-ossec.conf.snippet`), beri izin baca:

```bash
sudo usermod -a -G suricata wazuh
sudo chmod 750 /var/log/suricata
sudo systemctl enable --now wazuh-agent
```

> Jika agent gagal enroll (ERROR 1208 ke port 1515), pastikan `wazuh-authd`
> hidup di manager. Fix andal saat port tidak naik setelah boot (RAM mepet):
> ```bash
> sudo pkill -9 -f /var/ossec
> sudo rm -f /var/ossec/var/run/*.pid
> sudo systemctl restart wazuh-manager   # tunggu ~90 detik
> ```

## 4. Custom Wazuh rule

Tambahkan rule 100400 (dan 100500) ke `/var/ossec/etc/rules/local_rules.xml`
di manager (lihat `wazuh-rules/local_rules.xml`), lalu:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t    # validasi
sudo systemctl restart wazuh-manager
```

## 5. Verifikasi end-to-end

Dari Kali `sudo nmap -sS -p 1-1000 192.168.56.10`, lalu di dashboard
Threat Hunting: query `rule.id:100400` → alert **level 12** dengan
deskripsi IP dinamis + MITRE T1046.
