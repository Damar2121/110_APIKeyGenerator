// db.js
const mysql = require('mysql2');

// Konfigurasi koneksi database
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',             // Default XAMPP username
    password: '',             // Default XAMPP password (kosong)
    database: 'db_user_system', // Pastikan nama database ini sesuai dengan yang Anda buat di MySQL
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Export menggunakan promise agar bisa menggunakan async/await
module.exports = pool.promise();