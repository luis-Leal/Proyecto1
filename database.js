const Database = require('better-sqlite3');

const db = new Database('mibase.db');

// Crear tabla de usuarios con contraseña
db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        email TEXT UNIQUE,
        password TEXT
    )
`);

console.log('Base de datos lista');