# 🛡️ Sistem Informasi Manajemen Laundry Kiloan (Secure Version)

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

**Versi Rilis:** `v1.0-secure` (Final Release)

---

## 🚀 Gambaran Proyek

Sistem ini dirancang sebagai aplikasi pencatatan transaksi kasir lokal yang mengelola:

- Pencatatan transaksi laundry secara otomatis.
- Manajemen data pelanggan (PII).
- Manajemen pengguna dengan tingkat hak akses yang berbeda (Pemilik vs Karyawan).

---

## 🛡️ Ringkasan Keamanan (Security Posture)

Aplikasi ini telah melewati serangkaian fase pengujian dan pengerasan (_hardening_) keamanan tingkat lanjut dari Minggu 1 hingga Minggu 4:

1. **Authentication (Kriptografi):** Penyimpanan kata sandi menggunakan hashing **Bcrypt** dengan _Cost Factor_ 12.
2. **Input Validation (Anti-SQLi):** Penerapan **Parameterized Queries** secara menyeluruh pada operasi _database_ SQLite untuk memblokir SQL Injection.
3. **Access Control (RBAC & IDOR):** - Pemisahan hak akses menggunakan fungsi _Middleware_ untuk memproteksi halaman _Admin Panel_.
   - Penambalan celah IDOR (Insecure Direct Object Reference) dengan memvalidasi kepemilikan data melalui ID Sesi server, bukan parameter URL.
4. **Web Security:** - Konfigurasi **HTTP Security Headers** menggunakan library `Helmet.js`.
   - Proteksi sesi aman menggunakan kuki dengan atribut `HttpOnly`, `SameSite: strict`, dan `maxAge`.
   - Mitigasi serangan _Cross-Site Scripting_ (XSS) melalui _escape rendering_ otomatis pada _template engine_ EJS.
5. **Monitoring & Alerting:** - Implementasi pencatatan log aktivitas terstruktur dalam format JSON.
   - Proteksi **Anti Brute-Force** yang secara otomatis mengunci IP penyerang selama 5 menit jika terdeteksi 5 kali kegagalan login secara berturut-turut.

---

## 🛠️ Stack Teknologi

Sistem ini dibangun menggunakan arsitektur MVC (Model-View-Controller) yang solid:

- **Frontend/UI:** EJS (Embedded JavaScript Templating) & CSS murni.
- **Backend Logic:** Node.js dengan _framework_ Express.js.
- **Database:** SQLite (Sistem basis data portabel lokal).
- **Security Middleware:** Helmet, Express-Session, Bcrypt.

---

## ⚙️ Panduan Instalasi & Cara Menjalankan

Ikuti langkah-langkah di bawah ini untuk menjalankan aplikasi di lingkungan lokal:

1. **Clone Repositori:**

   ```bash
   git clone [https://github.com/MuhRafliansyah/2330205030043_SenyumKematian_Minggu1_RepositoryGit.git](https://github.com/MuhRafliansyah/2330205030043_SenyumKematian_Minggu1_RepositoryGit.git)

   cd 2330205030043_SenyumKematian_Minggu1_RepositoryGit

   ```

2. Instalasi Dependensi:

   ```Bash
   npm install

   ```

3. Konfigurasi Environment:
   - Ubah nama file .env.example menjadi .env.
   - Sesuaikan secret keys dan parameter lainnya jika diperlukan.

4. Inisialisasi Database (Hanya untuk penggunaan pertama):

   ```Bash
   node initDb.js

   ```

5. Jalankan Server Aplikasi:

   ```Bash
   node src/app.js

   Aplikasi dapat diakses melalui browser pada alamat http://localhost:3000.
   ```

Akun Testing (Dummy Data):
Hak Akses Pemilik (Admin): admin / admin123
Hak Akses Karyawan (User): budi / budi123
