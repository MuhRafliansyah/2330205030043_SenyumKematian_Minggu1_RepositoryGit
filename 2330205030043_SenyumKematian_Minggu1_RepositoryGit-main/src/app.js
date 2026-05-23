const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
require("dotenv").config();

const app = express();

// 1. SETTING VIEW ENGINE & FOLDER STATIS
app.set("view engine", "ejs");
app.use(express.static("public")); // Agar style.css di dalam public/assets bisa diakses

// 2. MIDDLEWARE KEAMANAN & PARSING BODY
app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Untuk menangani form POST

// 3. KONFIGURASI MANAJEMEN SESI YANG AMAN (Sesuai Checklist OWASP)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "rahasia-super-aman",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // AMAN: Mencegah akses token dari JavaScript (Mitigasi XSS)
      secure: process.env.NODE_ENV === "production", // Wajib HTTPS saat production
      maxAge: 15 * 60 * 1000, // AMAN: Sesi otomatis kedaluwarsa dalam 15 menit
      sameSite: "strict", // AMAN: Mencegah cookie dikirim dari situs lain (Mitigasi CSRF)
    },
  }),
);

// 4. KONEKSI DATABASE SQLITE
const dbPath = process.env.DB_PATH || "./laundry_data.sqlite";
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Gagal terhubung ke database SQLite:", err.message);
  } else {
    console.log("Terhubung ke database SQLite.");
  }
});

// 5. MIDDLEWARE AUTENTIKASI (Pencegah Bypass Halaman)
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/login");
  }
  next(); // Lolos validasi, lanjutkan ke route berikutnya
}

// ==========================================
// 6. DAFTAR ROUTE APLIKASI
// ==========================================

// Route Utama - Mengarahkan langsung ke halaman login
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Tampilkan Halaman Login
app.get("/login", (req, res) => {
  // Jika pengguna sudah memiliki sesi aktif, langsung arahkan ke dashboard
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }
  res.render("login", { error: null });
});

// Proses Form Login (Anti-SQLi & Verifikasi Bcrypt)
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // AMAN: Menggunakan Parameterized Query (?) untuk memitigasi SQL Injection
  const query = `SELECT id, username, password_hash, role FROM users WHERE username = ?`;

  db.get(query, [username], async (err, user) => {
    if (err) {
      console.error(err);
      return res.render("login", {
        error: "Terjadi kesalahan internal pada server.",
      });
    }

    // Proteksi: Jika user tidak ditemukan, tetap berikan pesan error generik
    if (!user) {
      return res.render("login", { error: "Username atau password salah!" });
    }

    try {
      // AMAN: Membandingkan password input dengan hash di database menggunakan bcrypt
      const match = await bcrypt.compare(password, user.password_hash);

      if (match) {
        // Login Berhasil: Daftarkan data pengguna ke dalam sesi aman
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.userRole = user.role;

        return res.redirect("/dashboard");
      } else {
        return res.render("login", { error: "Username atau password salah!" });
      }
    } catch (bcryptErr) {
      console.error(bcryptErr);
      return res.render("login", {
        error: "Terjadi kesalahan saat memproses kredensial.",
      });
    }
  });
});

// Halaman Dashboard (Diproteksi dengan Middleware requireLogin)
app.get("/dashboard", requireLogin, (req, res) => {
  res.render("dashboard", {
    user: {
      username: req.session.username,
      role: req.session.userRole,
    },
  });
});

// 1. Profil (Menambal IDOR: Hanya mengambil data sesuai ID Session)
app.get("/profile", requireLogin, (req, res) => {
  const userId = req.session.userId; // Mengabaikan parameter URL (?id=) untuk mencegah manipulasi ID
  db.get(
    `SELECT id, username, role, full_name, phone FROM users WHERE id = ?`,
    [userId],
    (err, userData) => {
      if (err || !userData)
        return res.status(404).send("Data tidak ditemukan.");
      res.render("profile", { user: req.session, userData });
    },
  );
});

// 2. Data Pelanggan (Menambal XSS: Menggunakan Parameterized Query & Sanitasi Otomatis EJS)
app.get("/customers", requireLogin, (req, res) => {
  const q = req.query.q || "";
  db.all(
    `SELECT * FROM customers WHERE name LIKE ?`,
    [`%${q}%`],
    (err, customers) => {
      if (err) return res.status(500).send("Terjadi kesalahan data.");
      res.render("customers", { user: req.session, customers, q });
    },
  );
});

// 3. Transaksi (Melihat dan Menambahkan Transaksi Baru secara Aman)
app.get("/transactions", requireLogin, (req, res) => {
  db.all(`SELECT * FROM customers`, (err, customers) => {
    if (err) return res.status(500).send("Terjadi kesalahan data.");
    db.all(
      `SELECT t.*, c.name FROM transactions t JOIN customers c ON t.customer_id = c.id ORDER BY t.id DESC`,
      (err, transactions) => {
        if (err) return res.status(500).send("Terjadi kesalahan data.");
        res.render("transactions", {
          user: req.session,
          customers,
          transactions,
          msg: null,
        });
      },
    );
  });
});

app.post("/transactions", requireLogin, (req, res) => {
  const { customer_id, weight, service } = req.body;
  const price = weight * 7000;

  // AMAN: Menggunakan Parameterized Query untuk mencegah SQLi pada input transaksi
  db.run(
    `INSERT INTO transactions (customer_id, weight, service, total_price, status, created_by) VALUES (?, ?, ?, ?, 'Proses', ?)`,
    [customer_id, weight, service, price, req.session.userId],
    (err) => {
      if (err) return res.status(500).send("Gagal menyimpan transaksi.");
      res.redirect("/transactions");
    },
  );
});

// 4. Admin Panel (Menambal Broken Access Control: Validasi Tingkat Peran / RBAC)
app.get("/admin", requireLogin, (req, res) => {
  if (req.session.userRole !== "admin") {
    return res
      .status(403)
      .send("Akses Ditolak: Fitur ini hanya untuk Pemilik (Admin).");
  }
  db.all(
    `SELECT t.*, c.name FROM transactions t JOIN customers c ON t.customer_id = c.id ORDER BY t.id DESC`,
    (err, transactions) => {
      if (err) return res.status(500).send("Terjadi kesalahan data.");
      res.render("admin", { user: req.session, transactions });
    },
  );
});

// 5. Fitur Delete Transaksi (Diproteksi Akses Admin & Parameterized Query)
app.get("/delete", requireLogin, (req, res) => {
  if (req.session.userRole !== "admin") {
    return res.status(403).send("Akses Ditolak!");
  }
  db.run(`DELETE FROM transactions WHERE id = ?`, [req.query.id], (err) => {
    if (err) return res.status(500).send("Gagal menghapus data.");
    res.redirect("/admin");
  });
});

// Proses Akses Logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Gagal menghapus sesi:", err);
    }
    res.redirect("/login");
  });
});

// ==========================================
// 7. JALANKAN SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server aman berjalan di port ${PORT}`);
});
