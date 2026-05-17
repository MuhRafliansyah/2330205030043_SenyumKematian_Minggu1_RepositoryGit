const sqlite3 = require("sqlite3").verbose();
// Path database diambil dari .env (bukan hardcoded)
const db = new sqlite3.Database(process.env.DB_PATH);

function getUserByUsername(username) {
  return new Promise((resolve, reject) => {
    // AMAN: Menggunakan Parameterized Query (?) untuk input username
    const query = `SELECT id, username, password_hash, role FROM users WHERE username = ?`;

    db.get(query, [username], (err, row) => {
      if (err) {
        // AMAN: Tidak mereturn error SQL syntax bawaan ke pengguna
        return reject(new Error("Gagal mengambil data pengguna."));
      }
      resolve(row);
    });
  });
}
