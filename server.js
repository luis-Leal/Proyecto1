const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
const SECRET = 'mi_clave_secreta';

app.use(express.json());
app.use(express.static('public'));

// ── AUTENTICACIÓN ──────────────────────────────

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
    if (!usuario) return res.status(400).json({ error: 'Usuario no encontrado' });
    const passwordCorrecta = bcrypt.compareSync(password, usuario.password);
    if (!passwordCorrecta) return res.status(400).json({ error: 'Contraseña incorrecta' });
    const token = jwt.sign({ id: usuario.id, nombre: usuario.nombre }, SECRET);
    res.json({ mensaje: 'Login exitoso', token, nombre: usuario.nombre });
});

// Middleware para verificar token
function verificarToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'No autorizado' });
    try {
        req.usuario = jwt.verify(token, SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ── CRUD DE USUARIOS ───────────────────────────

// Obtener todos los usuarios
app.get('/api/usuarios', verificarToken, (req, res) => {
    const usuarios = db.prepare('SELECT id, nombre, email, rol, fecha_creacion FROM usuarios').all();
    res.json(usuarios);
});

// Crear usuario
app.post('/api/usuarios', verificarToken, (req, res) => {
    const { nombre, email, password, rol } = req.body;
    const passwordEncriptada = bcrypt.hashSync(password, 10);
    try {
        db.prepare('INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)')
          .run(nombre, email, passwordEncriptada, rol || 'usuario');
        res.json({ mensaje: 'Usuario creado exitosamente' });
    } catch (error) {
        res.status(400).json({ error: 'El email ya está registrado' });
    }
});

// Editar usuario
app.put('/api/usuarios/:id', verificarToken, (req, res) => {
    const { nombre, email, rol } = req.body;
    db.prepare('UPDATE usuarios SET nombre = ?, email = ?, rol = ? WHERE id = ?')
      .run(nombre, email, rol, req.params.id);
    res.json({ mensaje: 'Usuario actualizado exitosamente' });
});

// Eliminar usuario
app.delete('/api/usuarios/:id', verificarToken, (req, res) => {
    db.prepare('DELETE FROM usuarios WHERE id = ?').run(req.params.id);
    res.json({ mensaje: 'Usuario eliminado exitosamente' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});