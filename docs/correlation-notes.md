# Correlation rule network ↔ host — catatan & tuning

Dokumen ini jujur mencatat status rule **100500** (correlation multi-stage)
yang **belum selesai** pada saat penulisan, beserta analisis penyebab dan
rencana perbaikan. Didokumentasikan apa adanya karena proses diagnosis ini
sendiri adalah bagian dari detection engineering.

## Tujuan

Menyalakan satu alert "multi-stage attack" level 14 ketika satu attacker
(IP sama) memicu, dalam jendela waktu yang sama:
1. alert **network** — port scan (rule 100400), dan
2. alert **host** — password spraying (rule 100300).

## Rule saat ini

```xml
<rule id="100500" level="14" frequency="2" timeframe="300">
  <if_sid>100300</if_sid>
  <if_matched_sid>100400</if_matched_sid>
  <description>MULTI-STAGE ATTACK: recon network (scan) diikuti serangan host dari attacker yang sama</description>
  <mitre><id>T1046</id><id>T1110.003</id></mitre>
  <options>no_full_log</options>
</rule>
```

## Status pengujian

- Rule **lolos validasi** `wazuh-analysisd -t` dan ter-load.
- Komponen pemicu jelas nyala saat rantai serangan nmap→spraying dijalankan:
  - `grep -c '"id":"100400"'` → ratusan (alert network)
  - `grep -c '"id":"100300"'` → beberapa (alert host)
- **Namun** `grep '"id":"100500"'` → **0**. Rule korelasi tidak pernah
  menjadi alert final.

## Hambatan teknis yang teridentifikasi

**Field IP berbeda antara dua sumber alert:**

| Sumber alert | Field IP attacker |
|---|---|
| Network (Suricata 100400) | `srcip` = 192.168.56.40 (Wazuh memetakan `src_ip` → `srcip`) |
| Host (spraying 100300) | `win.eventdata.ipAddress` = 192.168.56.40 (TIDAK ada `srcip`) |

Karena alert host tidak mengisi `srcip`, helper `same_source_ip` **tidak
bisa** membandingkan IP antar kedua sumber. Versi berbasis waktu murni
(`if_sid` + `if_matched_sid` tanpa perbandingan IP) juga belum trigger —
kemungkinan struktur `if_sid` + `if_matched_sid` di Wazuh 4.14.9 memerlukan
bentuk yang berbeda dan perlu diriset, bukan ditebak.

Catatan lain: `frequency` minimal bernilai **2** (nilai 1 ditolak dengan
`ERROR: Invalid frequency`).

## Rencana perbaikan (future work)

1. **Riset struktur yang benar** untuk composite rule di Wazuh 4.14.x —
   apakah `if_sid` + `if_matched_sid` boleh digabung dalam satu rule, atau
   korelasi harus dibentuk bertingkat (rule perantara).
2. **Normalisasi `srcip` di alert host** — buat custom decoder/rule yang
   menyalin `win.eventdata.ipAddress` → `srcip`, sehingga kedua sumber
   punya field IP yang sama. Setelah itu `same_source_ip` dapat dipakai
   untuk korelasi strict (IP benar-benar sama, bukan sekadar dua alert
   dalam jendela waktu).
3. Uji ulang end-to-end dan dokumentasikan before/after.

## Lingkungan

- Wazuh v4.14.9 (manager + agent)
- Lab single-attacker (Kali 192.168.56.40) — dalam konteks ini, "dua alert
  dalam jendela waktu dari satu subnet" sudah cukup kuat sebagai sinyal,
  tetapi versi strict (perbandingan IP) tetap menjadi target.
