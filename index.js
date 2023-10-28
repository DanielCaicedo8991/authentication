// const app = require('./app')
// app.listen(3030)
// console.log('Servidor corriendo en puerto ---> 3030',)

require('dotenv').config();

const express = require('express');
const admin = require('firebase-admin');
const serviceAccount = require('./firebase.json'); // Reemplaza con la ubicación de tu clave de servicio de Firebase
const bcrypt = require('bcrypt');
const cors = require('cors');


admin.initializeApp({
  credential: admin.credential.cert(serviceAccount), 
});

const app = express();
const port = process.env.PORT || 3030;

const db = admin.firestore();

// Middleware para analizar JSON en solicitudes
app.use(express.json());
app.use(cors());

// Función para encriptar una contraseña
async function encriptarContrasena(contrasena) {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  const contrasenaEncriptada = await bcrypt.hash(contrasena, salt);
  return contrasenaEncriptada;
}

// Ruta para el registro de usuarios
app.post('/registro', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Verificar si el correo ya está registrado en Firestore
    const querySnapshot = await db.collection('users').where('email', '==', email).get();

    if (!querySnapshot.empty) {
      // El correo ya está registrado
      return res.status(400).json({ success: false, error: 'El correo ya está registrado' });
    }

    // Encriptar la contraseña
    const passwordEncriptada = await encriptarContrasena(password);

    // Registra al usuario en Firebase Authentication
    const userRecord = await admin.auth().createUser({
      email,
      password: passwordEncriptada, // Almacena la contraseña encriptada en Firebase Auth
      displayName,
      passwordHash: passwordEncriptada,
    });

    // Guarda los datos del usuario en Firestore
    const userRef = db.collection('users').doc(userRecord.uid);
    await userRef.set({
      displayName,
      email,
      password: passwordEncriptada,
      passwordHash: passwordEncriptada, // Almacena la contraseña encriptada en Firestore
    });

    res.json({ success: true, data: userRecord });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


app.post('/create-user', async (req, res) => {
    
    try {
      const { email, name, id } = req.body;      
  
      // Verificar si el correo ya está registrado en Firestore
      const querySnapshot = await db.collection('users').where('email', '==', email).get();
  
      if (!querySnapshot.empty) {
        // El correo ya está registrado
        return res.status(400).json({ success: false, error: 'El correo ya está registrado' });
      }
  
      // Guarda los datos del usuario en Firestore
      const userRef = db.collection('users').doc(id);
      await userRef.set({
        name,
        email,
        id
            
      });
  
      res.json({ success: true, data: userRef });
    } catch (error) {
     
      res.status(500).json({ success: false, error: error.message });
    }
  });



app.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
  
      // Verificar si el correo es válido
      const userQuery = await db.collection('users').where('email', '==', email).get();

      if (userQuery.empty) {
        return res.status(401).json({ success: false, error: 'Usuario no encontrado' });
      }

      // Tomar el primer resultado de la consulta
      const userDoc = userQuery.docs[0];

      // Extraer la contraseña almacenada en el documento
      const storedPassword = userDoc.get('password');

      // Comprobar la contraseña
      const contrasenaValida = await bcrypt.compare(password, storedPassword);

      if (contrasenaValida) {
        res.json({ success: true, message: 'Inicio de sesión exitoso' });
      } else {
        res.status(401).json({ success: false, error: 'Credenciales incorrectas' });
      }
    } catch (error) {
      console.error('Error al iniciar sesión:', error);
      res.status(500).json({ success: false, error: error.message });
    }
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor en funcionamiento en el puerto ${port}`);
});