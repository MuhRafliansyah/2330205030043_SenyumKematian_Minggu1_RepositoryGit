const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
require("dotenv").config();

// Mengambil konfigurasi dari file .env
const dbPath = process.env.DB_PATH || "./laundry_data.sqlite";
const saltRounds = parseInt(process.env.PASSWORD_SALT_ROUNDS) || 12;

const db = new sqlite3.Database(dbPath);

async function initializeDB() {
  console.log(`Mulai inisialisasi database di: ${dbPath}...`);

  try {
    // 1. Melakukan hashing password dummy terlebih dahulu
    console.log(
      `Sedang melakukan hashing password dengan salt rounds: ${saltRounds}...`,
    );
    const adminHash = await bcrypt.hash("admin123", saltRounds);
    const budiHash = await bcrypt.hash("budi123", saltRounds);
    const andiHash = await bcrypt.hash("andi123", saltRounds);

    db.serialize(() => {
      // 2. Hapus tabel lama jika file dijalankan ulang (Reset)
      db.run("DROP TABLE IF EXISTS transactions");
      db.run("DROP TABLE IF EXISTS customers");
      db.run("DROP TABLE IF EXISTS users");

      // 3. Buat Tabel SQLite
      db.run(`
        CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          full_name TEXT,
          phone TEXT
        )
      `);

      db.run(`
        CREATE TABLE customers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          phone TEXT,
          address TEXT
        )
      `);

      db.run(`
        CREATE TABLE transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          customer_id INTEGER,
          weight INTEGER,
          service TEXT,
          total_price INTEGER,
          status TEXT,
          created_by INTEGER,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // 4. Insert Data Users dengan Password Hash
      const insertUser = db.prepare(
        `INSERT INTO users (username, password_hash, role, full_name, phone) VALUES (?, ?, ?, ?, ?)`,
      );
      insertUser.run(
        "admin",
        adminHash,
        "admin",
        "Pemilik Laundry",
        "081111111111",
      );
      insertUser.run("budi", budiHash, "user", "Budi Karyawan", "082222222222");
      insertUser.run("andi", andiHash, "user", "Andi Karyawan", "083333333333");
      insertUser.finalize();

      // 5. Insert Data Customers
      const insertCustomer = db.prepare(
        `INSERT INTO customers (name, phone, address) VALUES (?, ?, ?)`,
      );
      insertCustomer.run("Pelanggan Budi", "081234567890", "Jl. Merdeka No. 1");
      insertCustomer.run(
        "Pelanggan Andi",
        "089876543210",
        "Jl. Rajawali No. 2",
      );
      insertCustomer.run("Ibu Sari", "087711223344", "Jl. Kenanga No. 3");
      insertCustomer.finalize();

      // 6. Insert Data Transactions
      const insertTx = db.prepare(
        `INSERT INTO transactions (customer_id, weight, service, total_price, status, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
      );
      insertTx.run(1, 3, "Cuci Kering", 21000, "Selesai", 2);
      insertTx.run(2, 5, "Cuci Setrika", 35000, "Proses", 3);
      insertTx.run(3, 2, "Cuci Express", 14000, "Selesai", 2);
      insertTx.finalize();

      console.log("Struktur tabel dan data dummy berhasil dimasukkan!");
      console.log("Database SQLite siap digunakan.");
    });
  } catch (error) {
    console.error("Terjadi kesalahan saat inisialisasi:", error);
  }
}

// Jalankan fungsi inisialisasi
initializeDB();
