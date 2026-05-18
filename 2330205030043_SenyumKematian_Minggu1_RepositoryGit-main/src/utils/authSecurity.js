const bcrypt = require("bcrypt");

// Sesuai materi kuliah: Work factor (cost) diatur minimal 12
const SALT_ROUNDS = 12;

async function hashPassword(plainTextPassword) {
  try {
    // Generate salt dan hash password
    const hash = await bcrypt.hash(plainTextPassword, SALT_ROUNDS);
    return hash;
  } catch (err) {
    // Penanganan error tanpa membocorkan stack trace
    throw new Error("Terjadi kesalahan internal saat memproses kredensial.");
  }
}
