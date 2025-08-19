// =================================================================
// 1. IMPORTACIONES
// =================================================================
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');

// =================================================================
// 2. CONFIGURACIÓN INICIAL
// =================================================================
const app = express();
const PORT = 3000;

// Configurar EJS como el motor de plantillas
app.set('view engine', 'ejs');

// =================================================================
// 3. MIDDLEWARES
// =================================================================
// Middleware para analizar los datos de los formularios (URL-encoded)
app.use(express.urlencoded({ extended: true }));

// Middleware para gestionar las sesiones de usuario
app.use(session({
    secret: 'mi_secreto_para_el_club_privado_12345', // Cambia esto por un secreto real y seguro
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Para desarrollo. En producción, debería ser 'true' con HTTPS.
}));

// =================================================================
// 4. "BASE DE DATOS" EN MEMORIA
// =================================================================
// Un array para guardar los usuarios. En una app real, esto sería una base de datos.
const users = [];

// =================================================================
// 5. MIDDLEWARE DE AUTENTICACIÓN (EL "GUARDIÁN")
// =================================================================
// Esta función verifica si el usuario ha iniciado sesión antes de darle acceso a una ruta protegida.
const isAuth = (req, res, next) => {
    if (req.session.userId) {
        // Si hay un ID de usuario en la sesión, permite el paso.
        next();
    } else {
        // Si no, lo redirige a la página de inicio de sesión.
        res.redirect('/login');
    }
};

// =================================================================
// 6. RUTAS DE LA APLICACIÓN
// =================================================================

// --- Rutas Públicas ---

// Ruta principal (Página de inicio)
app.get('/', (req, res) => {
    res.render('home');
});

// Ruta para mostrar el formulario de registro
app.get('/registro', (req, res) => {
    res.render('registro');
});

// Ruta para procesar el registro de un nuevo usuario
app.post('/registro', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Comprueba si el usuario ya existe
        const userExists = users.find(user => user.email === email);
        if (userExists) {
            return res.send('El email ya está en uso. Por favor, elige otro.');
        }

        // Hashea la contraseña antes de guardarla
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crea y guarda el nuevo usuario
        const newUser = {
            id: Date.now().toString(),
            email,
            password: hashedPassword
        };
        users.push(newUser);

        console.log('Usuario nuevo registrado:', newUser); // Para depuración
        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.redirect('/registro');
    }
});

// Ruta para mostrar el formulario de inicio de sesión
app.get('/login', (req, res) => {
    res.render('login');
});

// Ruta para procesar el inicio de sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.send('Credenciales incorrectas (usuario no encontrado).');
    }

    try {
        // Compara la contraseña ingresada con la almacenada en la "base de datos"
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (passwordMatch) {
            // Contraseña correcta: Inicia la sesión guardando el ID del usuario
            req.session.userId = user.id;
            res.redirect('/perfil');
        } else {
            res.send('Credenciales incorrectas (contraseña no válida).');
        }
    } catch (error) {
        console.error(error);
        res.redirect('/login');
    }
});

// --- Rutas Protegidas ---

// Ruta del perfil, protegida por el middleware 'isAuth'
app.get('/perfil', isAuth, (req, res) => {
    // Aquí podrías buscar los datos del usuario usando req.session.userId si fuera necesario
    res.render('perfil');
});

// Ruta para cerrar la sesión del usuario
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            // Si hay un error al destruir la sesión, no se puede hacer mucho
            return res.redirect('/perfil');
        }
        res.clearCookie('connect.sid'); // Limpia la cookie de la sesión del navegador
        res.redirect('/');
    });
});

// =================================================================
// 7. INICIAR EL SERVIDOR
// =================================================================
app.listen(PORT, () => {
    console.log(`🚀 Servidor del Club Privado corriendo en http://localhost:${PORT}`);
});
