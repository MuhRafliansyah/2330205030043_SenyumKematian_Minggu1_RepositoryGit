// Fungsi middleware untuk mengecek peran (RBAC)
function checkRole(requiredRole) {
  return (req, res, next) => {
    // Sesi diambil dari HttpOnly Cookie yang tidak bisa dibaca oleh Javascript klien
    const userRole = req.session.userRole;

    if (!userRole) {
      // Pesan error generik dan kode status HTTP yang tepat (401 Unauthorized)
      return res
        .status(401)
        .json({ error: "Sesi tidak valid atau telah berakhir." });
    }

    if (userRole !== requiredRole) {
      // Kode 403 Forbidden untuk akses yang ditolak
      return res
        .status(403)
        .json({ error: "Akses ditolak: Privilese akun Anda tidak mencukupi." });
    }

    // Lolos validasi otorisasi, lanjutkan ke logika utama (controller)
    next();
  };
}

// Contoh Proteksi Endpoint (Hanya bisa diakses Pemilik)
// router.get('/api/laporan-keuangan', checkRole('Pemilik'), getLaporanKeuangan);
