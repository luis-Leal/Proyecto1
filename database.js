const Database = require('better-sqlite3');

const db = new Database('mibase.db');

// Tabla de usuarios con todos los campos
db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT DEFAULT 'usuario',
        fecha_creacion TEXT DEFAULT (datetime('now'))
    )
`);

module.exports = db;