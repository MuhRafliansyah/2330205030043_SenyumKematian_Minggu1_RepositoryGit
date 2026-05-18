const express = require("express");
const session = require("express-session");
const helmet = require("helmet"); // Memanggil helmet untuk Security Headers
require("dotenv").config();

const app = express();

// Tambahan: Menggunakan helmet untuk mengaktifkan Security Headers secara otomatis
app.use(helmet());

// Konfigurasi Manajemen Sesi yang Aman (Sesuai Checklist OWASP #6 & #7)
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

app.use(express.json());

// Simulasi endpoint utama
app.get("/", (req, res) => {
  res.json({ message: "Sistem Pencatatan Laundry Aman Berjalan!" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server aman berjalan di port ${PORT}`);
});
