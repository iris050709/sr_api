const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const connection = require('./db');
const multer = require('multer');
const path = require('path');
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const fs = require('fs');
const jwt = require('jsonwebtoken'); 
const { sendResetEmail } = require('./mailer'); 

router.post('/send-reset-code', (req, res) => {
    const { correo } = req.body;

    if (!correo) {
        return res.status(400).json({ message: 'Correo no proporcionado' });
    }

    const resetCode = Math.floor(100000 + Math.random() * 900000);  // Código aleatorio de 6 dígitos
    const expirationTime = new Date(Date.now() + 15 * 60000); // Expiración en 15 minutos

    // Insertar el código en la base de datos
    connection.query(
        'UPDATE usuarios SET resetCode = ?, resetCodeExpiration = ? WHERE correo = ?',
        [resetCode, expirationTime, correo],
        (err, results) => {
            if (err) {
                console.error('Error al insertar el código:', err);
                return res.status(500).json({ message: 'Error al enviar el código de recuperación', error: err });
            }

            if (results.affectedRows > 0) {
                // Enviar el correo de recuperación
                sendResetEmail(correo, resetCode);

                return res.status(200).json({ message: 'Código de recuperación enviado correctamente' });
            } else {
                return res.status(404).json({ message: 'Correo no encontrado en la base de datos' });
            }
        }
    );
});

router.post('/verify-reset-code', (req, res) => {
  const { correo, codigo } = req.body;

  console.log("Datos recibidos:", correo, codigo);

  if (!correo || !codigo) {
      return res.status(400).json({ message: "Correo y código son obligatorios." });
  }

  connection.query(
      "SELECT resetCode, resetCodeExpiration FROM usuarios WHERE correo = ?",
      [correo],
      (err, results) => {
          if (err) {
              console.error("Error al verificar el código:", err);
              return res.status(500).json({ message: "Error del servidor." });
          }

          if (results.length === 0) {
              return res.status(400).json({ message: "Correo no encontrado." });
          }

          const user = results[0];

          // Convertir ambos valores a string para comparación segura
          if (!user.resetCode || user.resetCode.toString() !== codigo.toString()) {
              return res.status(400).json({ message: "Código incorrecto." });
          }

          const now = new Date();
          if (new Date(user.resetCodeExpiration) < now) {
              return res.status(400).json({ message: "Código expirado." });
          }

          return res.status(200).json({ success: true, message: "Código correcto." });
      }
  );
});


router.post("/reset-password", async (req, res) => {
  const { correo, codigo, nuevaPassword } = req.body;

  try {
    // Consulta para buscar el usuario por correo
    const [rows] = await connection.promise().query('SELECT * FROM usuarios WHERE correo = ?', [correo]);

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: "Usuario no encontrado." });
    }

    const usuario = rows[0];

    // Verificar si el código coincide y no ha expirado
    if (!usuario.resetCode || usuario.resetCode !== codigo || Date.now() > usuario.resetCodeExpiration) {
      return res.status(400).json({ success: false, message: "Código inválido o expirado." });
    }

    // Hashear la nueva contraseña
    const hashedPassword = await bcrypt.hash(nuevaPassword, 10);

    // Actualizar la contraseña y limpiar el código de restablecimiento
    await connection.promise().query('UPDATE usuarios SET password = ?, resetCode = NULL, resetCodeExpiration = NULL WHERE correo = ?', [hashedPassword, correo]);

    res.json({ success: true, message: "Contraseña restablecida con éxito." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Error en el servidor." });
  }
});

const SECRET_KEY = "tu_secreto_super_seguro"; // Usa variables de entorno en producción
router.post("/update-password", async (req, res) => {
  const { correo, nuevaPassword } = req.body;

  if (!correo || !nuevaPassword) {
      return res.status(400).json({ error: "Datos incompletos." });
  }

  try {
      // Verificar si el correo existe en la base de datos
      connection.query(
          "SELECT id FROM usuarios WHERE correo = ?",
          [correo],
          async (err, results) => {
              if (err) {
                  console.error("Error en la consulta de usuario:", err);
                  return res.status(500).json({ error: "Error en el servidor." });
              }

              if (results.length === 0) {
                  return res.status(400).json({ error: "El correo no está registrado." });
              }

              const userId = results[0].id;
              const hashedPassword = await bcrypt.hash(nuevaPassword, 10);

              // Actualizar la contraseña en la base de datos
              connection.query(
                  "UPDATE usuarios SET password = ? WHERE id = ?",
                  [hashedPassword, userId],
                  (err) => {
                      if (err) {
                          console.error("Error al actualizar la contraseña:", err);
                          return res.status(500).json({ error: "Error al actualizar la contraseña." });
                      }
                      res.json({ success: true, message: "Contraseña actualizada con éxito." });
                  }
              );
          }
      );
  } catch (error) {
      console.error("Error en el servidor:", error);
      return res.status(500).json({ error: "Error en el servidor." });
  }
});

router.post("/login", (req, res) => {
  const { correo, password } = req.body;

  if (!correo || !password) {
    return res.status(400).json({ error: "Todos los campos son obligatorios." });
  }

  connection.query(
    "SELECT * FROM usuarios WHERE correo = ?",
    [correo],
    async (err, results) => {
      if (err) {
        console.error("Error al consultar usuario:", err);
        return res.status(500).json({ error: "Error interno del servidor." });
      }

      if (results.length === 0) {
        return res.status(401).json({ error: "Correo o contraseña incorrectos." });
      }

      const usuario = results[0];

      // Verificamos la contraseña con bcrypt
      const match = await bcrypt.compare(password, usuario.password);
      if (!match) {
        return res.status(401).json({ error: "Correo o contraseña incorrectos." });
      }

      // Generamos un token JWT
      const token = jwt.sign(
        { id: usuario.id, correo: usuario.correo, rol: usuario.rol },
        SECRET_KEY,
        { expiresIn: "2h" }
      );

      // Extraer solo el nombre del archivo de la imagen
      const fotoNombre = usuario.foto ? path.basename(usuario.foto) : null;

      res.json({
        success: true,
        message: "Inicio de sesión exitoso.",
        usuario: {
          id: usuario.id,
          nombre: usuario.nombre,
          correo: usuario.correo,
          rol: usuario.rol,
          sexo: usuario.sexo,
          fecha_nacimiento: usuario.fecha_nacimiento,
          foto: fotoNombre, // Solo el nombre del archivo
        },
        token,
      });
    }
  );
});


router.get('/api/perfil', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acceso denegado' });
  jwt.verify(token, 'secreto', (err, decoded) => {
      if (err) return res.status(403).json({ error: 'Token inválido' });
      connection.query('SELECT nombre, correo, rol, sexo, fecha_nacimiento, foto FROM usuarios WHERE id = ?', [decoded.id], (err, results) => {
          if (err || results.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
          res.json(results[0]);
      });
  });
});

// Configuración de almacenamiento para multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

// Ruta para registrar usuario
router.post("/usuarios", upload.single('foto'), (req, res) => {
    console.log("📥 Datos recibidos:", req.body);
    console.log("📸 Archivo recibido:", req.file);

    const { nombre, correo, password, rol, fecha_nacimiento, sexo } = req.body;
    const foto = req.file ? req.file.path : null;

    if (!nombre || !correo || !password || !fecha_nacimiento || !sexo || !foto) {
        console.log("❌ Error: Faltan campos obligatorios");
        return res.status(400).json({ error: "Todos los campos son obligatorios" });
    }

    // Función para calcular la edad
    const calcularEdad = (fechaNacimiento) => {
        const hoy = new Date();
        const nacimiento = new Date(fechaNacimiento);
        let edad = hoy.getFullYear() - nacimiento.getFullYear();
        const mes = hoy.getMonth() - nacimiento.getMonth();
        if (mes < 0 || (mes === 0 && hoy.getDate() < nacimiento.getDate())) {
            edad--;
        }
        return edad;
    };

    // Validar que el usuario tenga al menos 18 años
    if (calcularEdad(fecha_nacimiento) < 18) {
        console.log("⛔ Error: Usuario menor de edad");
        return res.status(403).json({ error: "Debes tener al menos 18 años para registrarte" });
    }

    // Verificar si el correo ya existe
    const checkEmailQuery = "SELECT * FROM usuarios WHERE correo = ?";
    connection.query(checkEmailQuery, [correo], (err, results) => {
        if (err) {
            console.error("❌ Error al verificar correo:", err);
            return res.status(500).json({ error: "Error en el servidor" });
        }

        console.log("🔎 Resultados de búsqueda de correo:", results);

        if (results.length > 0) {
            console.log("⚠️ El correo ya está registrado:", correo);
            return res.status(400).json({ error: "El correo ya está registrado" });
        }

        // Encriptar contraseña antes de guardarla
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                console.error("❌ Error al encriptar la contraseña:", err);
                return res.status(500).json({ error: "Error al encriptar la contraseña" });
            }

            // Insertar usuario en la base de datos
            const insertQuery = "INSERT INTO usuarios (nombre, correo, password, rol, foto, fecha_nacimiento, sexo) VALUES (?, ?, ?, ?, ?, ?, ?)";
            connection.query(insertQuery, [nombre, correo, hashedPassword, rol, foto, fecha_nacimiento, sexo], (err, result) => {
                if (err) {
                    console.error("❌ Error al registrar usuario:", err);
                    return res.status(500).json({ error: "Error al registrar usuario" });
                }
                console.log("✅ Usuario registrado con éxito:", result.insertId);
                res.status(201).json({ message: "✅ Usuario registrado con éxito", fotoUrl: foto });
            });
        });
    });
});



// Obtener todos los usuarios
router.get('/usuarios', (req, res) => {
  connection.query('SELECT * FROM usuarios', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Ruta para login de usuario
// Ruta para iniciar sesión (login)
// Ruta para iniciar sesión (login)




// Ruta para validar si el correo existe
router.post("/login/validate", (req, res) => {
  const { correo } = req.body;

  if (!correo) {
    return res.status(400).json({ error: "Correo es requerido" });
  }

  // Consultar el usuario por correo
  const query = "SELECT * FROM usuarios WHERE correo = ?";
  connection.query(query, [correo], (err, results) => {
    if (err) {
      console.error("Error al consultar el correo:", err);
      return res.status(500).json({ error: "Error al consultar el correo" });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: "Correo no registrado" });
    }

    // Si el correo existe, respondemos con un mensaje de éxito
    res.status(200).json({ message: "Correo válido" });
  });
});


// Middleware para verificar el JWT (si usas JWT)
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Obtenemos el token de la cabecera

  if (!token) return res.status(401).json({ error: 'Acceso denegado. No se encontró el token.' });

  jwt.verify(token, 'mi_secreto', (err, user) => { // 'mi_secreto' es la clave que usas para firmar el JWT
      if (err) return res.status(403).json({ error: 'Token no válido' });
      req.user = user; // Aquí guardamos la información del usuario
      next();
  });
};

// Ruta para obtener el perfil del usuario por ID
router.get('/usuarios/:id', verifyToken, (req, res) => {
  const id = req.params.id;

  if (req.user.id !== id) {
      return res.status(403).json({ error: 'No tienes permiso para acceder a este perfil' });
  }

  const query = 'SELECT id, nombre, correo, rol, sexo, fecha_nacimiento, foto FROM usuarios WHERE id = ? LIMIT 1';
  connection.query(query, [id], (err, results) => {
      if (err) {
          console.error('Error al obtener el perfil:', err);
          return res.status(500).json({ error: 'Error al obtener el perfil' });
      }

      if (results.length === 0) {
          return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      res.json(results[0]);
  });
});



// Obtener todos los sensores
router.get('/sensores', (req, res) => {
  connection.query('SELECT * FROM sensores', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener un sensor por su ID
router.get('/sensores/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM sensores WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todos los registros de sensores
router.get('/registros_sensores', (req, res) => {
  connection.query('SELECT * FROM registros_sensores', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener un registro de sensor por su ID
router.get('/registros_sensores/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM registros_sensores WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todas las válvulas
router.get('/valvulas', (req, res) => {
  connection.query('SELECT * FROM valvulas', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener una válvula por su ID
router.get('/valvulas/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM valvulas WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todos los riegos realizados
router.get('/riegos', (req, res) => {
  connection.query('SELECT * FROM riegos', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener un riego realizado por su ID
router.get('/riegos/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM riegos WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todas las configuraciones de riego
router.get('/configuraciones_riego', (req, res) => {
  connection.query('SELECT * FROM configuraciones_riego', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener una configuración de riego por su ID
router.get('/configuraciones_riego/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM configuraciones_riego WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

// Obtener todas las alertas
router.get('/alertas', (req, res) => {
  connection.query('SELECT * FROM alertas', (err, results) => {
    if (err) {
      console.error('Error al obtener registros:', err);
      res.status(500).json({ error: 'Error al obtener registros' });
      return;
    }
    res.json(results);
  });
});

// Obtener una alerta por su ID
router.get('/alertas/:id', (req, res) => {
  const id = req.params.id;
  connection.query('SELECT * FROM alertas WHERE id = ?', id, (err, results) => {
    if (err) {
      console.error('Error al obtener el registro:', err);
      res.status(500).json({ error: 'Error al obtener el registro' });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: 'Registro no encontrado' });
      return;
    }
    res.json(results[0]);
  });
});

module.exports = router;
