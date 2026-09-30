# ReCheck

> **Bahasa Indonesia** · [English](README.en.md)

Verifikasi integritas berkas langsung dari terminal, dengan **SHA-256** atau
**MD5**. Gaya perintah ala nmap, tanpa dependensi, jalan di Linux, macOS, dan
Windows.

```console
$ recheck -f ./contoh_file.txt
ReCheck report for ./contoh_file.txt
Size: 3 B   Time: 0.00 s   Throughput: 28.1 KB/s
sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
ReCheck done: 1 file hashed in 0.00 seconds
```

Setelah terpasang, `recheck` bisa dipanggil dari direktori mana saja.

---

## Instalasi

Butuh **Python 3.9** atau lebih baru. Belum punya? Ambil dari
[python.org/downloads](https://www.python.org/downloads/). Di Windows, centang
**"Add python.exe to PATH"** saat instalasi.

### 1. Pasang pipx

`pipx` membuat virtualenv terpisah per aplikasi, jadi Python sistem Anda tidak
tersentuh. Ini cara yang benar untuk distro yang mengunci Python sistemnya
(PEP 668 — Kali, Fedora, Debian 12+, Ubuntu 23.10+).

| Sistem | Perintah |
|---|---|
| Debian / Ubuntu / Kali | `sudo apt install pipx && pipx ensurepath` |
| Fedora | `sudo dnf install pipx` |
| Arch | `sudo pacman -S pipx` |
| macOS | `brew install pipx && pipx ensurepath` |
| Windows | `pipx install pipx && pipx ensurepath` |

### 2. Pasang ReCheck

Perintah yang sama untuk **Linux, macOS, dan Windows**:

```bash
pipx install git+https://github.com/1RenXc/ReCheck.git
```

>`pipx ensurepath` menambahkan folder script ke `PATH`. Jalankan sekali saja,
>setelah itu tutup dan buka terminal kembali.

### Verifikasi

```console
$ recheck -V
recheck 1.0.0 ( https://github.com/1RenXc/ReCheck )
```

Kalau itu muncul, ReCheck siap dipakai.

---

## Cara Pakai

Alurnya tiga langkah: **hash** berkas → **simpan** ke manifest → **verifikasi**
kapan-kapan dibutuhkan.

```console
# 1. Rekam baseline saat pertama kali memercayai berkas
$ recheck -f ./folder -c baseline.sha256

# 2. Di kemudian hari, pastikan tidak ada yang berubah
$ recheck -v baseline.sha256
ReCheck report for ./folder/a.txt
Size: 3 B   Time: 0.00 s   Throughput: 41.7 KB/s
sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
MATCH: expected checksum

ReCheck done: 1 file verified in 0.00 seconds
$ echo $?
0
```

---

## Opsi

```
recheck -f <file|directory> [Options]
```

| Opsi | Arti |
|---|---|
| `-f <path>` | Target berkas atau direktori. Dapat diulang. Direktori dipindai rekursif |
| `-c <file>` | Simpan hash yang dihitung ke berkas manifest |
| `-v <file\|hash>` | Verifikasi terhadap manifest **atau** nilai hash langsung |
| `-a <alg>` | Algoritma untuk generate **dan** bandingkan. Default `sha256` |
| `-V` | Nomor versi |
| `-h`, `--help` | Bantuan lengkap |

Nama panjang `--file`, `--create`, `--verify`, `--algorithm`, `--version`,
`--help` juga tersedia.

### Algoritma

| Nama | Panjang | Catatan |
|---|---|---|
| `sha256` | 256-bit | **Default.** Pilihan untuk verifikasi integritas |
| `md5` | 128-bit | Hanya kompatibilitas sistem lama. Bukan untuk keamanan |

Daftar ini dibaca langsung dari kode, jadi selalu akurat di `recheck -h`.

---

## Exit Code

| Code | Arti |
|---|---|
| `0` | Semua berkas cocok |
| `1` | Ditemukan hash yang tidak cocok (`MISMATCH`) |
| `2` | Kesalahan penggunaan (opsi tidak dikenal, `-c` bersama `-v`, dll) |
| `3` | Berkas tidak ditemukan atau error I/O |

Siap dipakai di script dan CI:

```bash
if recheck -v baseline.sha256; then
    echo "integritas terverifikasi"
else
    echo "PERINGATAN: integritas bermasalah"
    exit 1
fi
```

---

## Contoh

```bash
# Cetak hash ke layar
recheck -f ./contoh_file.txt

# Hash berlabel, tidak perlu mengingat panjang digit
recheck -f ./contoh_file.txt -v 'md5:900150983cd24fb0d6963f7d28e17f72' -a md5

# Generate dengan md5
recheck -f ./contoh_file.txt -a md5 -c contoh_file.md5.txt

# Verifikasi seluruh isi folder, rekursif
recheck -f ./folder -c baseline.sha256
recheck -v baseline.sha256

# Beberapa berkas sekaligus
recheck -f a.bin -f b.bin -c checksums.txt
```

Cari tahu file mana yang berubah:

```bash
recheck -v baseline.sha256 | grep -B4 MISMATCH
```

---

## Interoperabilitas

Manifest ReCheck memakai format GNU coreutils, jadi bisa dibaca `sha256sum` — dan
sebaliknya:

```bash
# Manifest ReCheck -> coreutils
recheck -f iso.img -c iso.sha256
sha256sum -c --strict iso.sha256

# Manifest coreutils -> ReCheck
sha256sum iso.img > iso.sha256
recheck -v iso.sha256
```

Berlaku juga untuk `md5sum`. Berguna kalau pipeline Anda sudah bergantung pada
`sha256sum -c`, misalnya di Dockerfile, Jenkins, atau GitHub Actions.

---

## Update

```bash
pipx install --force git+https://github.com/1RenXc/ReCheck.git
```

## Menghapus

```bash
pipx uninstall recheck
```

---

## Troubleshooting

### `recheck: command not found`

Paket terpasang, tapi folder script belum ada di `PATH`. Jalankan sekali:

```bash
pipx ensurepath
```

Lalu **buka terminal baru** — `PATH` hanya dibaca saat terminal dimulai.

### `error: externally-managed-environment`

Distro Anda melindungi Python sistem dari pemasangan paket mentah (PEP 668).
Itulah sebabnya ReCheck dipasang lewat `pipx`, yang memakai virtualenv terpisah
dan tidak menyentuh Python sistem.

### `Permission denied` saat hashing

Hashing butuh hak baca. Untuk berkas milik root:

```bash
sudo recheck -f /etc/shadow
```

### Hash berbeda antar mesin

Harus begitu. SHA-256 menghasilkan nilai yang sama untuk input yang sama di
semua platform. Kalau berbeda, berarti berkasnya memang berbeda — bukan
ReCheck-nya yang salah.

---

## Lisensi

[MIT](LICENSE) © ReCheck contributors
