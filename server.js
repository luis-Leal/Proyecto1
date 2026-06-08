const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const db = new Database('mibase.db');
const SECRET = 'mi_clave_secreta';

app.use(express.json());
app.use(express.static('public'));

// Registro
app.post('/api/registro', (req, res) => {
    const { nombre, email, password } = req.body;

    const passwordEncriptada = bcrypt.hashSync(password, 10);

    try {
        db.prepare('INSERT INTO usuarios (nombre, email, password) VALUES (?, ?, ?)')
          .run(nombre, email, passwordEncriptada);
        res.json({ mensaje: 'Usuario registrado exitosamente' });
    } catch (error) {
        res.status(400).json({ error: 'El email ya está registrado' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    const usuario = db.prepare('SELECT * FROM usuarios WHERE email = ?').get(email);

    if (!usuario) {
        return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const passwordCorrecta = bcrypt.compareSync(password, usuario.password);

    if (!passwordCorrecta) {
        return res.status(400).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ id: usuario.id, nombre: usuario.nombre }, SECRET);
    res.json({ mensaje: 'Login exitoso', token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});