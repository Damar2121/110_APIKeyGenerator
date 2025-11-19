// server.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const db = require('./db'); // Pastikan file db.js sudah ada dan benar

const app = express();
const PORT = 3000;

// --- MIDDLEWARE ---
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public'))); // Melayani file HTML dari folder public

app.use(session({
    secret: 'kunci_rahasia_admin_123', // Bisa diganti string acak
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Sesi 24 jam
}));

// Middleware Cek Login Admin
const isAuthenticated = (req, res, next) => {
    if (req.session.adminId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized. Silakan login.' });
    }
};

// --- ROUTES ---

// 1. REGISTER USER (Logic Diubah: Menerima API Key dari Frontend)
app.post('/api/user/register', async (req, res) => {
    // Kita ambil 'apiKey' dari body karena sudah digenerate di HTML
    const { firstName, lastName, email, apiKey } = req.body;

    // Validasi: Pastikan API Key tidak kosong
    if (!apiKey) {
        return res.redirect('/index.html?status=error_no_key');
    }

    try {
        // Langkah A: Simpan API Key ke tabel ApiKey
        const [keyResult] = await db.query('INSERT INTO ApiKey (`Key`) VALUES (?)', [apiKey]);
        const newKeyId = keyResult.insertId;

        // Langkah B: Simpan Data User (Hubungkan dengan ID ApiKey tadi)
        await db.query(
            'INSERT INTO User (First_name, Last_name, Email, ApiKeyID) VALUES (?, ?, ?, ?)', 
            [firstName, lastName, email, newKeyId]
        );

        // Sukses
        res.redirect('/index.html?status=success');

    } catch (error) {
        console.error(error);
        // Kemungkinan error: Email sudah ada atau API Key duplikat (sangat jarang untuk UUID)
        res.redirect('/index.html?status=error');
    }
});

// 2. REGISTER ADMIN
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO Admin (Email, Password) VALUES (?, ?)', [email, hashedPassword]);
        res.redirect('/admin_login.html?registered=true');
    } catch (error) {
        res.send("Gagal register. Email mungkin sudah digunakan.");
    }
});

// 3. LOGIN ADMIN
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [admins] = await db.query('SELECT * FROM Admin WHERE Email = ?', [email]);
        
        if (admins.length === 0) {
            return res.redirect('/admin_login.html?error=notfound');
        }

        const admin = admins[0];
        const match = await bcrypt.compare(password, admin.Password);

        if (match) {
            req.session.adminId = admin.ID;
            res.redirect('/dashboard.html');
        } else {
            res.redirect('/admin_login.html?error=wrongpass');
        }
    } catch (error) {
        console.error(error);
        res.send("Server Error");
    }
});

// 4. API DASHBOARD DATA (Protected)
app.get('/api/dashboard/data', isAuthenticated, async (req, res) => {
    try {
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
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: "Database Error" });
    }
});

// 5. DELETE USER (Protected)
app.delete('/api/user/delete/:id', isAuthenticated, async (req, res) => {
    try {
        await db.query('DELETE FROM ApiKey WHERE ID = ?', [req.params.id]);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false });
    }
});

// 6. LOGOUT
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/admin_login.html'));
});

app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});