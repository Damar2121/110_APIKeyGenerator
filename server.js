// server.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const db = require('./db'); // Import file db.js yang dibuat tadi

const app = express();
const PORT = 3000;

// --- MIDDLEWARE ---
// 1. Parsing data form dan JSON
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// 2. Setup Folder Public (agar file HTML, CSS, Gambar bisa diakses)
// Pastikan file index.html, admin_login.html, dll ada di dalam folder bernama 'public'
app.use(express.static(path.join(__dirname, 'public')));

// 3. Setup Session (Untuk Login)
app.use(session({
    secret: 'rahasia_kunci_server_anda', // Bisa diganti dengan string acak apa saja
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Sesi berlaku 24 jam
}));

// --- FUNGSI BANTUAN (Authentication Check) ---
// Middleware untuk memastikan user sudah login sebelum akses API dashboard
const isAuthenticated = (req, res, next) => {
    if (req.session.adminId) {
        next();
    } else {
        // Jika belum login, kirim status 401 (Unauthorized)
        res.status(401).json({ error: 'Unauthorized' });
    }
};

// --- ROUTES / JALUR LOGIKA ---

// 1. REGISTER USER BARU (Public)
// Menerima data dari form di index.html
app.post('/api/user/register', async (req, res) => {
    const { firstName, lastName, email } = req.body;
    const newApiKey = uuidv4(); // Generate UUID otomatis

    try {
        // Langkah A: Simpan API Key ke tabel ApiKey
        const [keyResult] = await db.query('INSERT INTO ApiKey (`Key`) VALUES (?)', [newApiKey]);
        const newKeyId = keyResult.insertId;

        // Langkah B: Simpan Data User ke tabel User (Menghubungkan dengan ID ApiKey)
        await db.query(
            'INSERT INTO User (First_name, Last_name, Email, ApiKeyID) VALUES (?, ?, ?, ?)', 
            [firstName, lastName, email, newKeyId]
        );

        // Jika sukses, kembalikan ke halaman utama dengan parameter sukses & key
        res.redirect('/index.html?status=success&key=' + newApiKey);

    } catch (error) {
        console.error(error);
        // Jika gagal (misal email duplikat), kembalikan dengan parameter error
        res.redirect('/index.html?status=error');
    }
});

// 2. REGISTER ADMIN (Public)
// Menerima data dari form admin_register.html
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Hash password sebelum disimpan (Security)
        const hashedPassword = await bcrypt.hash(password, 10);

        // Simpan ke database
        await db.query('INSERT INTO Admin (Email, Password) VALUES (?, ?)', [email, hashedPassword]);

        // Redirect ke login dengan pesan sukses
        res.redirect('/admin_login.html?registered=true');

    } catch (error) {
        console.error(error);
        res.send("Gagal mendaftar. Email admin mungkin sudah digunakan.");
    }
});

// 3. LOGIN ADMIN (Public)
// Menerima data dari form admin_login.html
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Cari admin berdasarkan email
        const [admins] = await db.query('SELECT * FROM Admin WHERE Email = ?', [email]);

        // Jika email tidak ditemukan
        if (admins.length === 0) {
            return res.redirect('/admin_login.html?error=notfound');
        }

        const adminData = admins[0];

        // Cek apakah password cocok dengan hash di database
        const isMatch = await bcrypt.compare(password, adminData.Password);

        if (isMatch) {
            // Login Berhasil: Buat sesi
            req.session.adminId = adminData.ID;
            req.session.email = adminData.Email;
            
            // Arahkan ke Dashboard
            res.redirect('/dashboard.html');
        } else {
            // Password Salah
            res.redirect('/admin_login.html?error=wrongpass');
        }

    } catch (error) {
        console.error(error);
        res.send("Terjadi kesalahan pada server.");
    }
});

// 4. GET DATA DASHBOARD (Protected)
// API ini dipanggil oleh JavaScript di dashboard.html menggunakan Fetch
app.get('/api/dashboard/data', isAuthenticated, async (req, res) => {
    try {
        // Query Logika Status:
        // Jika 'last_active' lebih lama dari 30 hari yang lalu -> Nonaktif
        const query = `
            SELECT 
                u.ID, 
                u.First_name, 
                u.Last_name, 
                u.Email, 
                ak.ID as KeyId, 
                ak.Key as ApiKey,
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
        
        // Kirim data dalam format JSON ke frontend
        res.json(users);

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Database Error" });
    }
});

// 5. DELETE USER (Protected)
app.delete('/api/user/delete/:id', isAuthenticated, async (req, res) => {
    const keyId = req.params.id;

    try {
        // Hapus dari tabel ApiKey (Tabel User akan ikut terhapus karena CONSTRAINT ON DELETE CASCADE di SQL)
        await db.query('DELETE FROM ApiKey WHERE ID = ?', [keyId]);
        
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false });
    }
});

// 6. LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return console.log(err);
        }
        res.redirect('/admin_login.html');
    });
});

// --- JALANKAN SERVER ---
app.listen(PORT, () => {
    console.log(`--------------------------------------------------`);
    console.log(`Server Berjalan! Akses di: http://localhost:${PORT}`);
    console.log(`--------------------------------------------------`);
});