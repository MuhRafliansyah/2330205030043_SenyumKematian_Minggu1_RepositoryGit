# 🛡️ Sistem Pencatatan Keuangan Laundry Kiloan (Secure-Laundry-App)

Selamat datang di repositori Proyek **Secure Software Engineering (SSE)**. Proyek ini bertujuan untuk mendigitalisasi operasional usaha laundry kiloan dengan fokus utama pada integritas data keuangan dan perlindungan privasi pelanggan melalui metodologi **S-SDLC (Secure Software Development Life Cycle)**.

---

## 👥 Profil Kelompok

**Nama Kelompok:** SenyumKematian  
**Institusi:** Teknik Informatika, Universitas Palangka Raya (UPR)

| Nama Anggota              | NIM           | Peran Utama      |
| :------------------------ | :------------ | :--------------- |
| **Muhamad Rafliansyah**   | 2330205030043 | Ketua Kelompok   |
| **Muhammad Arifin Ilham** | 2330205030034 | Anggota Kelompok |
| **Athay Setya Dwi Putri** | 2330105030024 | Anggota Kelompok |

---

## 🚀 Gambaran Proyek

Sistem ini dirancang sebagai aplikasi desktop lokal (_offline_) yang mengelola:

- Pencatatan transaksi laundry secara otomatis.
- Manajemen data pelanggan (PII).
- Pengelolaan pengeluaran operasional dan pendapatan.
- Laporan laba/rugi yang hanya dapat diakses oleh Pemilik.

### 🛡️ Fokus Keamanan (Minggu 1)

Proyek ini mengimplementasikan prinsip _Security by Design_ sejak fase perencanaan:

- **Threat Modeling:** Analisis ancaman menggunakan metodologi **STRIDE**.
- **Attack Tree:** Visualisasi skenario serangan kritis terhadap aset bisnis.
- **Secure Architecture:** Penerapan _Layered Architecture_ dan _Principle of Least Privilege_.

---

## 🛠️ Stack Teknologi (Justifikasi Keamanan)

1. **Frontend/UI:** (Sebutkan Stack, misal: React/Electron) - Dipilih karena dukungan library sanitasi input yang kuat.
2. **Backend Logic:** Node.js - Memudahkan implementasi middleware keamanan.
3. **Database:** SQLite (Encrypted via SQLCipher) - Melindungi data _at-rest_ pada penyimpanan lokal.
4. **Security:** Bcrypt/Argon2 (Password Hashing) & Parameterized Queries (Anti-SQLi).

---

## ⚙️ Panduan Instalasi & Setup Keamanan

1. **Clone Repository:**
   ```bash
   git clone [https://github.com/MuhRafliansyah/2330205030043_SenyumKematian_Minggu1_RepositoryGit.git](https://github.com/MuhRafliansyah/2330205030043_SenyumKematian_Minggu1_RepositoryGit.git)
   ```
