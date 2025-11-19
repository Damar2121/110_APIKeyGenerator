// server.js - Final Version
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./db'); // Pastikan file db.js menggunakan host: '127.0.0.1'

const app = express();
const PORT = 3000;

// --- MIDDLEWARE ---
// 1. Parsing Body (agar bisa baca data dari form HTML)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// 2. Folder Public (Menyajikan file HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// 3. Konfigurasi Session (Agar admin tetap login)
app.use(session({
    secret: 'rahasia_dapur_server_ini', // Boleh diganti string acak
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Login berlaku 24 jam
}));

// --- FUNGSI CEK LOGIN (Proteksi Halaman) ---
const isAuthenticated = (req, res, next) => {
    if (req.session.adminId) {
        next(); // Lanjut kalau sudah login
    } else {
        // Tolak akses jika belum login
        res.status(401).json({ error: 'Akses ditolak. Silakan login admin.' });
    }
};

// ================= ROUTES / JALUR APLIKASI =================

// 1. API REGISTER USER (Data dari register_user.html)
app.post('/api/user/register', async (req, res) => {
    // Ambil data yang dikirim form
    const { firstName, lastName, email, apiKey } = req.body;

    // Cek apakah user sudah klik tombol generate di frontend
    if (!apiKey) {
        return res.redirect('/register_user.html?status=error_no_key');
    }

    try {
        // A. Simpan API Key dulu ke tabel ApiKey
        const [keyResult] = await db.query('INSERT INTO ApiKey (`Key`) VALUES (?)', [apiKey]);
        const newKeyId = keyResult.insertId;

        // B. Simpan Data User (nyambung ke ID ApiKey tadi)
        await db.query(
            'INSERT INTO User (First_name, Last_name, Email, ApiKeyID) VALUES (?, ?, ?, ?)', 
            [firstName, lastName, email, newKeyId]
        );

        // SUKSES: Balik ke halaman register_user.html
        res.redirect('/register_user.html?status=success');

    } catch (error) {
        // ERROR: Tampilkan error di terminal (biar admin tau)
        console.error("ERROR DATABASE:", error);

        // Kirim pesan error asli ke browser (biar user tau, misal email duplikat)
        const errorMessage = encodeURIComponent(error.sqlMessage || error.message);
        res.redirect('/register_user.html?status=error&msg=' + errorMessage);
    }
});

// 2. API REGISTER ADMIN
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Enkripsi password sebelum disimpan
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await db.query('INSERT INTO Admin (Email, Password) VALUES (?, ?)', [email, hashedPassword]);
        
        // Sukses, arahkan ke login
        res.redirect('/admin_login.html?registered=true');
    } catch (error) {
        console.error(error);
        res.send("Gagal register Admin. Email mungkin sudah terdaftar.");
    }
});

// 3. API LOGIN ADMIN
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Cari admin berdasarkan email
        const [admins] = await db.query('SELECT * FROM Admin WHERE Email = ?', [email]);

        // Jika email tidak ada
        if (admins.length === 0) {
            return res.redirect('/admin_login.html?error=notfound');
        }

        const adminData = admins[0];

        // Cek password (bandingkan input dengan hash di DB)
        const match = await bcrypt.compare(password, adminData.Password);

        if (match) {
            // Password Benar -> Buat Sesi
            req.session.adminId = adminData.ID;
            res.redirect('/dashboard.html'); // Masuk Dashboard
        } else {
            // Password Salah
            res.redirect('/admin_login.html?error=wrongpass');
        }
    } catch (error) {
        console.error(error);
        res.send("Terjadi kesalahan server saat login.");
    }
});

// 4. API GET DATA DASHBOARD (Hanya bisa diakses jika login)
app.get('/api/dashboard/data', isAuthenticated, async (req, res) => {
    try {
        // Query Status: Cek apakah manual revoked ATAU expired (lebih dari 30 hari tidak aktif)
        const query = `
            SELECT 
                u.ID, u.First_name, u.Last_name, u.Email, 
                ak.ID as KeyId, ak.Key as ApiKey,
                CASE 
                    WHEN ak.is_manually_revoked = 1 THEN 'Nonaktif (Manual)'
                    WHEN ak.last_active < NOW() - INTERVAL 1 MONTH THEN 'Nonaktif (Expired)'
                    ELSE 'Aktif'
                END AS Status_Key
            FROM User u
            JOIN ApiKey ak ON u.ApiKeyID = ak.ID
            ORDER BY u.ID DESC
        `;
        
        const [users] = await db.query(query);
        res.json(users); // Kirim data JSON ke frontend

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Gagal mengambil data database." });
    }
});

// 5. API DELETE USER (Hanya bisa diakses jika login)
app.delete('/api/user/delete/:id', isAuthenticated, async (req, res) => {
    const keyId = req.params.id;
    try {
        // Hapus ApiKey (User otomatis terhapus karena settingan MySQL CASCADE)
        await db.query('DELETE FROM ApiKey WHERE ID = ?', [keyId]);
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false });
    }
});

// 6. LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/admin_login.html'); // Balik ke login admin
    });
});

// JALANKAN SERVER
app.listen(PORT, () => {
    console.log(`----------------------------------------------------`);
    console.log(`Server Berjalan di: http://localhost:${PORT}`);
    console.log(`----------------------------------------------------`);
});