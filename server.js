// server.js - VERSIÓN COMPLETA INTEGRADA CON EDITOR ENRIQUECIDO Y NUEVAS FUNCIONALIDADES
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware básicos
app.use(helmet({
  crossOriginResourcePolicy: false, // Permitir recursos cross-origin para imágenes
}));
app.use(compression());

// Configuración CORS mejorada
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'http://localhost:5174',
      'http://127.0.0.1:5173',
      'https://pokerprotrack.com',
      'https://www.pokerprotrack.com'

    ];
    // Permitir requests sin origin (Postman, etc)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(null, true); // En desarrollo, permitir todos los orígenes
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' })); // Aumentar límite para contenido HTML con imágenes
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// IMPORTANTE: Servir archivos estáticos de uploads
// Esta línea es CRÍTICA para que las imágenes funcionen
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Verificar y crear carpetas necesarias
const uploadsDir = path.join(__dirname, 'uploads');
const newsUploadsDir = path.join(__dirname, 'uploads', 'news');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

if (!fs.existsSync(newsUploadsDir)) {
  fs.mkdirSync(newsUploadsDir, { recursive: true });
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // límite de 100 requests por IP
});
app.use('/api/', limiter);

// Database connection
const dbPath = path.join(__dirname, 'database', 'database.sqlite');
const dbDir = path.join(__dirname, 'database');

// Crear carpeta database si no existe
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initDatabase();
  }
});

// Initialize database tables
function initDatabase() {
  // Tabla de administradores
  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Tabla de noticias - ACTUALIZADA CON NUEVOS CAMPOS
  db.run(`
    CREATE TABLE IF NOT EXISTS news (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      excerpt TEXT NOT NULL,
      content TEXT NOT NULL,
      content_html TEXT,
      category TEXT NOT NULL,
      image TEXT,
      gallery TEXT,
      featured BOOLEAN DEFAULT 0,
      author TEXT DEFAULT 'Admin',
      views INTEGER DEFAULT 0,
      status TEXT DEFAULT 'published',
      tags TEXT,
      read_time INTEGER DEFAULT 5,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err && !err.message.includes('already exists')) {
      console.error('Error creando tabla news:', err);
    } else {
      // Intentar agregar nuevas columnas si la tabla ya existía
      db.run(`ALTER TABLE news ADD COLUMN content_html TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
          console.log('Columna content_html ya existe o error:', err.message);
        }
      });
      
      db.run(`ALTER TABLE news ADD COLUMN gallery TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
          console.log('Columna gallery ya existe o error:', err.message);
        }
      });
      
      db.run(`ALTER TABLE news ADD COLUMN read_time INTEGER DEFAULT 5`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
          console.log('Columna read_time ya existe o error:', err.message);
        }
      });
    }
  });

  // Tabla de usuarios para rakeback
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      initial_deposit REAL DEFAULT 0,
      bonus_amount REAL DEFAULT 0,
      bonus_released REAL DEFAULT 0,
      total_rake REAL DEFAULT 0,
      rakeback_percentage REAL DEFAULT 60,
      status TEXT DEFAULT 'active',
      current_rake_cycle REAL DEFAULT 0,
      total_milestones INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err && !err.message.includes('already exists')) {
      console.error('Error creando tabla users:', err);
    } else {
      // Agregar nuevas columnas para el sistema de rake mejorado
      db.run(`ALTER TABLE users ADD COLUMN current_rake_cycle REAL DEFAULT 0`, () => {});
      db.run(`ALTER TABLE users ADD COLUMN total_milestones INTEGER DEFAULT 0`, () => {});
    }
  });

  // Tabla de transacciones de rake
  db.run(`
    CREATE TABLE IF NOT EXISTS rake_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      bonus_released REAL DEFAULT 0,
      description TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Tabla de metas
  db.run(`
    CREATE TABLE IF NOT EXISTS goals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      target_amount REAL NOT NULL,
      current_progress REAL DEFAULT 0,
      reward_amount REAL DEFAULT 0,
      reward_type TEXT DEFAULT 'bonus',
      status TEXT DEFAULT 'active',
      deadline DATE,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Tabla de hitos de rake (para el nuevo sistema)
  db.run(`
    CREATE TABLE IF NOT EXISTS rake_milestones (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      milestone_amount REAL NOT NULL,
      bonus_released REAL NOT NULL,
      reached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Tabla de regalos del administrador
  db.run(`
    CREATE TABLE IF NOT EXISTS user_gifts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      gift_type TEXT NOT NULL,
      gift_value REAL NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'active',
      admin_id INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      claimed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (admin_id) REFERENCES admins (id)
    )
  `);

  // NUEVAS TABLAS - BONOS MÚLTIPLES
  db.run(`
    CREATE TABLE IF NOT EXISTS user_bonuses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      bonus_name TEXT NOT NULL,
      bonus_amount REAL NOT NULL,
      bonus_released REAL DEFAULT 0,
      bonus_type TEXT DEFAULT 'deposit',
      bonus_order INTEGER DEFAULT 1,
      status TEXT DEFAULT 'inactive',
      activation_condition TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      activated_at DATETIME,
      completed_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // NUEVA TABLA - REGALOS CONDICIONALES
  db.run(`
    CREATE TABLE IF NOT EXISTS conditional_gifts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      condition_type TEXT NOT NULL,
      condition_value REAL NOT NULL,
      gift_type TEXT NOT NULL,
      gift_value REAL NOT NULL,
      gift_title TEXT NOT NULL,
      gift_description TEXT,
      is_active BOOLEAN DEFAULT 1,
      is_global BOOLEAN DEFAULT 1,
      specific_user_id INTEGER,
      max_claims INTEGER DEFAULT 1,
      current_claims INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (specific_user_id) REFERENCES users (id)
    )
  `);

  // NUEVA TABLA - CLAIMS DE REGALOS CONDICIONALES
  db.run(`
    CREATE TABLE IF NOT EXISTS conditional_gift_claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      conditional_gift_id INTEGER NOT NULL,
      progress REAL DEFAULT 0,
      is_claimed BOOLEAN DEFAULT 0,
      claimed_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (conditional_gift_id) REFERENCES conditional_gifts (id)
    )
  `);
    

  // Crear admin por defecto si no existe
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@pokerprotrack.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin2024!';
  
  db.get("SELECT * FROM admins WHERE email = ?", [adminEmail], async (err, row) => {
    if (!row) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      db.run("INSERT INTO admins (email, password) VALUES (?, ?)", 
        [adminEmail, hashedPassword], 
        (err) => {
          if (!err) {
            console.log(`Admin created: ${adminEmail}`);
          }
        }
      );
    }
  });
}

// ==================== NUEVAS CONSTANTES ====================
const RAKE_MILESTONE = 50; // Cada 50 soles de rake
const MILESTONE_BONUS = 30; // Se liberan 30 soles

// Configuración de Multer para subir imágenes
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads', 'news');
    // Asegurar que la carpeta existe
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Solo se permiten imágenes (jpeg, jpg, png, gif, webp)'));
    }
  }
});

// Middleware de autenticación
const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No autorizado' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    req.adminId = decoded.id;
    next();
  });
};

// ==================== NUEVAS FUNCIONES HELPER ====================

// Función para calcular bonos por hitos
function calculateMilestoneBonus(currentRakeCycle, newRakeAmount) {
  const totalRake = currentRakeCycle + newRakeAmount;
  const milestonesReached = Math.floor(totalRake / RAKE_MILESTONE);
  const currentMilestones = Math.floor(currentRakeCycle / RAKE_MILESTONE);
  const newMilestones = milestonesReached - currentMilestones;
  
  return {
    newMilestones,
    bonusToRelease: newMilestones * MILESTONE_BONUS,
    newRakeCycle: totalRake % RAKE_MILESTONE,
    totalMilestones: milestonesReached
  };
}

// Activar siguiente bono (automático cuando se completa el actual)
const activateNextBonus = (userId) => {
  // Buscar el siguiente bono inactivo
  db.get(
    `SELECT * FROM user_bonuses 
     WHERE user_id = ? AND status = 'inactive' 
     ORDER BY bonus_order LIMIT 1`,
    [userId],
    (err, nextBonus) => {
      if (!err && nextBonus) {
        db.run(
          `UPDATE user_bonuses 
           SET status = 'active', activated_at = CURRENT_TIMESTAMP 
           WHERE id = ?`,
          [nextBonus.id],
          (err) => {
            if (!err) {
              console.log(`Bono activado para usuario ${userId}: ${nextBonus.bonus_name}`);
            }
          }
        );
      }
    }
  );
};

// Verificar y otorgar regalos condicionales automáticamente
const checkConditionalGifts = async (userId, conditionType, newValue) => {
  const query = `
    SELECT cg.* FROM conditional_gifts cg
    LEFT JOIN conditional_gift_claims cgc ON cg.id = cgc.conditional_gift_id AND cgc.user_id = ?
    WHERE cg.is_active = 1 
    AND cg.condition_type = ?
    AND (cg.is_global = 1 OR cg.specific_user_id = ?)
    AND (cgc.is_claimed IS NULL OR cgc.is_claimed = 0)
  `;

  db.all(query, [userId, conditionType, userId], (err, gifts) => {
    if (err || !gifts.length) return;

    gifts.forEach(gift => {
      // Verificar si se cumple la condición
      if (newValue >= gift.condition_value) {
        // Crear el regalo para el usuario
        const giftQuery = `
          INSERT INTO user_gifts (
            user_id, gift_type, gift_value, title, description, status
          )
          VALUES (?, ?, ?, ?, ?, 'active')
        `;

        db.run(giftQuery, [
          userId, 
          gift.gift_type, 
          gift.gift_value, 
          gift.gift_title, 
          gift.gift_description
        ], function(err) {
          if (!err) {
            // Marcar como reclamado
            const claimQuery = `
              INSERT OR REPLACE INTO conditional_gift_claims 
              (user_id, conditional_gift_id, progress, is_claimed, claimed_at)
              VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP)
            `;
            
            db.run(claimQuery, [userId, gift.id, newValue], (err) => {
              if (!err) {
                console.log(`Regalo condicional otorgado: ${gift.title} para usuario ${userId}`);
              }
            });
          }
        });
      } else {
        // Actualizar progreso
        const progressQuery = `
          INSERT OR REPLACE INTO conditional_gift_claims 
          (user_id, conditional_gift_id, progress, is_claimed)
          VALUES (?, ?, ?, 0)
        `;
        
        db.run(progressQuery, [userId, gift.id, newValue]);
      }
    });
  });
};

// ==================== RUTAS AUTH ====================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  db.get("SELECT * FROM admins WHERE email = ?", [email], async (err, admin) => {
    if (err || !admin) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    
    const token = jwt.sign(
      { id: admin.id, email: admin.email },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    
    res.json({ token, email: admin.email });
  });
});

// ==================== RUTAS NOTICIAS ====================

// Obtener todas las noticias (público)
app.get('/api/news', (req, res) => {
  const { category, featured, limit = 20, offset = 0 } = req.query;
  let query = "SELECT * FROM news WHERE status = 'published'";
  const params = [];
  
  if (category && category !== 'todas') {
    query += " AND category = ?";
    params.push(category);
  }
  
  if (featured === 'true') {
    query += " AND featured = 1";
  }
  
  query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(parseInt(limit), parseInt(offset));
  
  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    // Parsear gallery JSON si existe
    const newsWithParsedGallery = rows.map(row => {
      if (row.gallery) {
        try {
          row.gallery = JSON.parse(row.gallery);
        } catch (e) {
          row.gallery = [];
        }
      }
      return row;
    });
    res.json(newsWithParsedGallery);
  });
});

// Obtener noticia por slug (público)
app.get('/api/news/:slug', (req, res) => {
  const { slug } = req.params;
  
  db.get("SELECT * FROM news WHERE slug = ?", [slug], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }
    
    // Parsear gallery si existe
    if (row.gallery) {
      try {
        row.gallery = JSON.parse(row.gallery);
      } catch (e) {
        row.gallery = [];
      }
    }
    
    // Incrementar vistas
    db.run("UPDATE news SET views = views + 1 WHERE id = ?", [row.id]);
    
    res.json(row);
  });
});

// Crear noticia BÁSICA (mantener compatibilidad)
app.post('/api/admin/news', authenticateAdmin, upload.single('image'), (req, res) => {
  const { title, excerpt, content, category, featured, tags, status = 'published' } = req.body;
  
  // Generar slug desde el título
  const slug = title.toLowerCase()
    .replace(/[áàäâã]/g, 'a')
    .replace(/[éèëê]/g, 'e')
    .replace(/[íìïî]/g, 'i')
    .replace(/[óòöôõ]/g, 'o')
    .replace(/[úùüû]/g, 'u')
    .replace(/ñ/g, 'n')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
  
  // Construir la ruta de la imagen si se subió una
  let imagePath = null;
  if (req.file) {
    imagePath = `/uploads/news/${req.file.filename}`;
    console.log('Imagen guardada en:', imagePath);
  }
  
  const query = `
    INSERT INTO news (title, slug, excerpt, content, category, image, featured, tags, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  db.run(query, 
    [title, slug, excerpt, content, category, imagePath, featured === 'true' ? 1 : 0, tags, status],
    function(err) {
      if (err) {
        console.error('Error al crear noticia:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ 
        id: this.lastID, 
        slug, 
        image: imagePath,
        message: 'Noticia creada exitosamente' 
      });
    }
  );
});

// ==================== RUTAS PARA EDITOR ENRIQUECIDO ====================

// Subir imagen individual para el editor (admin)
app.post('/api/admin/upload-image', authenticateAdmin, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No se subió ninguna imagen' });
  }
  
  const imageUrl = `/uploads/news/${req.file.filename}`;
  console.log('Imagen del editor subida:', imageUrl);
  
  res.json({ 
    success: true,
    url: imageUrl,
    fullUrl: `http://localhost:${PORT}${imageUrl}`
  });
});

// Subir múltiples imágenes para galería (admin)
app.post('/api/admin/upload-gallery', authenticateAdmin, upload.array('images', 10), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No se subieron imágenes' });
  }
  
  const imageUrls = req.files.map(file => ({
    url: `/uploads/news/${file.filename}`,
    fullUrl: `http://localhost:${PORT}/uploads/news/${file.filename}`,
    filename: file.filename
  }));
  
  res.json({ 
    success: true,
    images: imageUrls
  });
});

// Crear noticia ENRIQUECIDA con editor moderno
app.post('/api/admin/news-rich', authenticateAdmin, upload.fields([
  { name: 'featuredImage', maxCount: 1 },
  { name: 'gallery', maxCount: 10 }
]), (req, res) => {
  const { 
    title, 
    excerpt, 
    content, 
    content_html, // Nuevo: contenido HTML del editor
    category, 
    featured, 
    tags, 
    status = 'published',
    read_time = 5 
  } = req.body;
  
  // Generar slug
  const slug = title.toLowerCase()
    .replace(/[áàäâã]/g, 'a')
    .replace(/[éèëê]/g, 'e')
    .replace(/[íìïî]/g, 'i')
    .replace(/[óòöôõ]/g, 'o')
    .replace(/[úùüû]/g, 'u')
    .replace(/ñ/g, 'n')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
  
  // Procesar imagen principal
  let imagePath = null;
  if (req.files['featuredImage'] && req.files['featuredImage'][0]) {
    imagePath = `/uploads/news/${req.files['featuredImage'][0].filename}`;
  }
  
  // Procesar galería
  let galleryPaths = [];
  if (req.files['gallery']) {
    galleryPaths = req.files['gallery'].map(file => `/uploads/news/${file.filename}`);
  }
  
  const query = `
    INSERT INTO news (
      title, slug, excerpt, content, content_html, category, 
      image, gallery, featured, tags, status, read_time
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  db.run(query, 
    [
      title, 
      slug, 
      excerpt, 
      content, 
      content_html || content, // Si no hay HTML, usar content normal
      category, 
      imagePath, 
      JSON.stringify(galleryPaths), // Guardar galería como JSON
      featured === 'true' ? 1 : 0, 
      tags, 
      status,
      read_time
    ],
    function(err) {
      if (err) {
        console.error('Error al crear noticia rica:', err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ 
        id: this.lastID, 
        slug, 
        image: imagePath,
        gallery: galleryPaths,
        message: 'Noticia creada exitosamente' 
      });
    }
  );
});

// Actualizar noticia ENRIQUECIDA
app.put('/api/admin/news-rich/:id', authenticateAdmin, upload.fields([
  { name: 'featuredImage', maxCount: 1 },
  { name: 'gallery', maxCount: 10 }
]), (req, res) => {
  const { id } = req.params;
  const { 
    title, 
    excerpt, 
    content, 
    content_html,
    category, 
    featured, 
    tags, 
    status,
    read_time,
    keepExistingGallery // Flag para mantener galería existente
  } = req.body;
  
  db.get("SELECT image, gallery FROM news WHERE id = ?", [id], (err, row) => {
    if (err || !row) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }
    
    // Procesar imagen principal
    let imagePath = row.image;
    if (req.files['featuredImage'] && req.files['featuredImage'][0]) {
      imagePath = `/uploads/news/${req.files['featuredImage'][0].filename}`;
      
      // Opcional: eliminar imagen anterior
      if (row.image) {
        const oldImagePath = path.join(__dirname, row.image);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
    }
    
    // Procesar galería
    let galleryPaths = [];
    if (keepExistingGallery === 'true' && row.gallery) {
      try {
        galleryPaths = JSON.parse(row.gallery);
      } catch (e) {
        galleryPaths = [];
      }
    }
    
    if (req.files['gallery']) {
      const newGalleryPaths = req.files['gallery'].map(file => `/uploads/news/${file.filename}`);
      galleryPaths = keepExistingGallery === 'true' 
        ? [...galleryPaths, ...newGalleryPaths]
        : newGalleryPaths;
    }
    
    const slug = title.toLowerCase()
      .replace(/[áàäâã]/g, 'a')
      .replace(/[éèëê]/g, 'e')
      .replace(/[íìïî]/g, 'i')
      .replace(/[óòöôõ]/g, 'o')
      .replace(/[úùüû]/g, 'u')
      .replace(/ñ/g, 'n')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '');
    
    const query = `
      UPDATE news 
      SET title = ?, slug = ?, excerpt = ?, content = ?, content_html = ?,
          category = ?, image = ?, gallery = ?, featured = ?, tags = ?, 
          status = ?, read_time = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;
    
    db.run(query,
      [
        title, 
        slug, 
        excerpt, 
        content,
        content_html || content,
        category, 
        imagePath, 
        JSON.stringify(galleryPaths),
        featured === 'true' ? 1 : 0, 
        tags, 
        status,
        read_time || 5,
        id
      ],
      (err) => {
        if (err) {
          console.error('Error al actualizar noticia rica:', err);
          return res.status(500).json({ error: err.message });
        }
        res.json({ 
          message: 'Noticia actualizada exitosamente',
          image: imagePath,
          gallery: galleryPaths
        });
      }
    );
  });
});

// Actualizar noticia BÁSICA (mantener compatibilidad)
app.put('/api/admin/news/:id', authenticateAdmin, upload.single('image'), (req, res) => {
  const { id } = req.params;
  const { title, excerpt, content, category, featured, tags, status } = req.body;
  
  db.get("SELECT image FROM news WHERE id = ?", [id], (err, row) => {
    if (err || !row) {
      return res.status(404).json({ error: 'Noticia no encontrada' });
    }
    
    // Si se sube una nueva imagen, usar esa. Si no, mantener la existente
    let imagePath = row.image;
    if (req.file) {
      imagePath = `/uploads/news/${req.file.filename}`;
      console.log('Nueva imagen guardada en:', imagePath);
      
      // Opcional: eliminar la imagen anterior
      if (row.image) {
        const oldImagePath = path.join(__dirname, row.image);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
    }
    
    const slug = title.toLowerCase()
      .replace(/[áàäâã]/g, 'a')
      .replace(/[éèëê]/g, 'e')
      .replace(/[íìïî]/g, 'i')
      .replace(/[óòöôõ]/g, 'o')
      .replace(/[úùüû]/g, 'u')
      .replace(/ñ/g, 'n')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)/g, '');
    
    const query = `
      UPDATE news 
      SET title = ?, slug = ?, excerpt = ?, content = ?, category = ?, 
          image = ?, featured = ?, tags = ?, status = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `;
    
    db.run(query,
      [title, slug, excerpt, content, category, imagePath, featured === 'true' ? 1 : 0, tags, status, id],
      (err) => {
        if (err) {
          console.error('Error al actualizar noticia:', err);
          return res.status(500).json({ error: err.message });
        }
        res.json({ 
          message: 'Noticia actualizada exitosamente',
          image: imagePath 
        });
      }
    );
  });
});

// Eliminar noticia (admin)
app.delete('/api/admin/news/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  
  // Primero obtener la imagen y galería para eliminarlas
  db.get("SELECT image, gallery FROM news WHERE id = ?", [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    // Eliminar imagen principal del servidor si existe
    if (row && row.image) {
      const imagePath = path.join(__dirname, row.image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
        console.log('Imagen principal eliminada:', imagePath);
      }
    }
    
    // Eliminar imágenes de galería si existen
    if (row && row.gallery) {
      try {
        const galleryPaths = JSON.parse(row.gallery);
        galleryPaths.forEach(galleryImage => {
          const galleryPath = path.join(__dirname, galleryImage);
          if (fs.existsSync(galleryPath)) {
            fs.unlinkSync(galleryPath);
            console.log('Imagen de galería eliminada:', galleryPath);
          }
        });
      } catch (e) {
        console.log('Error procesando galería:', e);
      }
    }
    
    // Eliminar la noticia de la base de datos
    db.run("DELETE FROM news WHERE id = ?", [id], (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Noticia eliminada exitosamente' });
    });
  });
});

// Obtener imágenes subidas (para galería del editor)
app.get('/api/admin/gallery-images', authenticateAdmin, (req, res) => {
  const galleryPath = path.join(__dirname, 'uploads', 'news');
  
  fs.readdir(galleryPath, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Error leyendo galería' });
    }
    
    const imageFiles = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);
    });
    
    const images = imageFiles.map(file => ({
      filename: file,
      url: `/uploads/news/${file}`,
      fullUrl: `http://localhost:${PORT}/uploads/news/${file}`
    }));
    
    res.json(images);
  });
});

// ==================== RUTAS RAKEBACK ====================

// Obtener todos los usuarios (admin)
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
  db.all("SELECT * FROM users ORDER BY created_at DESC", (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// NUEVA: Buscar usuarios (admin)
app.get('/api/admin/users/search', authenticateAdmin, (req, res) => {
  const { q } = req.query;
  
  if (!q || q.trim().length < 2) {
    return res.status(400).json({ error: 'Término de búsqueda muy corto' });
  }
  
  const searchTerm = `%${q.trim()}%`;
  const query = `
    SELECT * FROM users 
    WHERE username LIKE ? OR email LIKE ?
    ORDER BY username
    LIMIT 20
  `;
  
  db.all(query, [searchTerm, searchTerm], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Obtener usuario por username (público con auth simple)
app.get('/api/rakeback/:username', (req, res) => {
  const { username } = req.params;
  
  db.get(`
    SELECT id, username, email, initial_deposit, bonus_amount, 
           bonus_released, total_rake, rakeback_percentage, status, 
           current_rake_cycle, total_milestones, created_at
    FROM users WHERE username = ?
  `, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    // Obtener historial de transacciones
    db.all(
      "SELECT * FROM rake_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
      [user.id],
      (err, transactions) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        res.json({ user, transactions });
      }
    );
  });
});

// Crear usuario (admin)
app.post('/api/admin/users', authenticateAdmin, (req, res) => {
  const { username, email, phone, initial_deposit, bonus_amount, rakeback_percentage = 60 } = req.body;
  
  const query = `
    INSERT INTO users (username, email, phone, initial_deposit, bonus_amount, rakeback_percentage)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  
  db.run(query,
    [username, email, phone, initial_deposit, bonus_amount, rakeback_percentage],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ id: this.lastID, message: 'Usuario creado exitosamente' });
    }
  );
});

// ==================== SISTEMA DE RAKE MEJORADO ====================

// Agregar rake con nuevo sistema ORIGINAL
app.post('/api/admin/rake', authenticateAdmin, (req, res) => {
  const { user_id, rake_amount, description } = req.body;
  
  // Obtener datos del usuario
  db.get("SELECT * FROM users WHERE id = ?", [user_id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const rakeAmount = parseFloat(rake_amount);
    const currentCycle = user.current_rake_cycle || 0;
    
    // Calcular bonos por hitos
    const milestone = calculateMilestoneBonus(currentCycle, rakeAmount);
    
    // Verificar que no se exceda el bono máximo
    const remaining_bonus = user.bonus_amount - user.bonus_released;
    const actual_bonus_released = Math.min(milestone.bonusToRelease, remaining_bonus);
    
    // Actualizar usuario
    const new_total_rake = user.total_rake + rakeAmount;
    const new_bonus_released = user.bonus_released + actual_bonus_released;
    
    db.run(
      `UPDATE users 
       SET total_rake = ?, bonus_released = ?, current_rake_cycle = ?, 
           total_milestones = ?, updated_at = CURRENT_TIMESTAMP 
       WHERE id = ?`,
      [new_total_rake, new_bonus_released, milestone.newRakeCycle, milestone.totalMilestones, user_id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        
        // Registrar transacción
        db.run(
          `INSERT INTO rake_transactions (user_id, amount, bonus_released, description)
           VALUES (?, ?, ?, ?)`,
          [user_id, rakeAmount, actual_bonus_released, description],
          function(err) {
            if (err) {
              return res.status(500).json({ error: err.message });
            }
            
            // Si se alcanzaron hitos, registrarlos
            if (milestone.newMilestones > 0) {
              for (let i = 0; i < milestone.newMilestones; i++) {
                const milestoneNumber = milestone.totalMilestones - milestone.newMilestones + i + 1;
                const milestoneAmount = milestoneNumber * RAKE_MILESTONE;
                
                db.run(
                  `INSERT INTO rake_milestones (user_id, milestone_amount, bonus_released)
                   VALUES (?, ?, ?)`,
                  [user_id, milestoneAmount, MILESTONE_BONUS]
                );
              }
            }
            
            // Actualizar progreso de metas activas
            db.all(
              'SELECT * FROM goals WHERE user_id = ? AND status = "active"',
              [user_id],
              (err, goals) => {
                if (!err && goals.length > 0) {
                  goals.forEach(goal => {
                    const newProgress = Math.min(new_total_rake, goal.target_amount);
                    const isCompleted = newProgress >= goal.target_amount;
                    
                    db.run(
                      `UPDATE goals 
                       SET current_progress = ?, status = ?, 
                           completed_at = ?, updated_at = CURRENT_TIMESTAMP 
                       WHERE id = ?`,
                      [
                        newProgress, 
                        isCompleted ? 'completed' : 'active',
                        isCompleted ? new Date().toISOString() : null,
                        goal.id
                      ]
                    );
                  });
                }
              }
            );
            
            // Verificar regalos condicionales
            checkConditionalGifts(user_id, 'rake', new_total_rake);
            
            res.json({
              message: 'Rake agregado exitosamente',
              rake_amount: rakeAmount,
              bonus_released: actual_bonus_released,
              milestones_reached: milestone.newMilestones,
              current_cycle: milestone.newRakeCycle,
              next_milestone: RAKE_MILESTONE - milestone.newRakeCycle,
              remaining_bonus: remaining_bonus - actual_bonus_released,
              transaction_id: this.lastID
            });
          }
        );
      }
    );
  });
});

// NUEVO: Agregar rake con sistema de bonos múltiples
app.post('/api/admin/rake-improved', authenticateAdmin, (req, res) => {
  const { user_id, rake_amount, description } = req.body;
  
  // Obtener datos del usuario
  db.get("SELECT * FROM users WHERE id = ?", [user_id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    const rakeAmount = parseFloat(rake_amount);
    const currentCycle = user.current_rake_cycle || 0;
    
    // Calcular bonos por hitos (lógica existente)
    const milestone = calculateMilestoneBonus(currentCycle, rakeAmount);
    
    // Obtener bono activo actual
    db.get(
      'SELECT * FROM user_bonuses WHERE user_id = ? AND status = "active" ORDER BY bonus_order LIMIT 1',
      [user_id],
      (err, activeBonus) => {
        let bonusToRelease = milestone.bonusToRelease;
        
        // Si hay bono activo, usarlo en lugar del bono principal
        if (activeBonus) {
          const remaining = activeBonus.bonus_amount - activeBonus.bonus_released;
          bonusToRelease = Math.min(bonusToRelease, remaining);
          
          // Actualizar bono activo
          const newBonusReleased = activeBonus.bonus_released + bonusToRelease;
          db.run(
            'UPDATE user_bonuses SET bonus_released = ? WHERE id = ?',
            [newBonusReleased, activeBonus.id],
            (err) => {
              // Si se completó el bono, marcarlo como completado y activar el siguiente
              if (newBonusReleased >= activeBonus.bonus_amount) {
                db.run(
                  'UPDATE user_bonuses SET status = "completed", completed_at = CURRENT_TIMESTAMP WHERE id = ?',
                  [activeBonus.id],
                  () => {
                    activateNextBonus(user_id);
                  }
                );
              }
            }
          );
        }
        
        // Actualizar usuario (lógica existente)
        const new_total_rake = user.total_rake + rakeAmount;
        const new_bonus_released = user.bonus_released + bonusToRelease;
        
        db.run(
          `UPDATE users 
           SET total_rake = ?, bonus_released = ?, current_rake_cycle = ?, 
               total_milestones = ?, updated_at = CURRENT_TIMESTAMP 
           WHERE id = ?`,
          [new_total_rake, new_bonus_released, milestone.newRakeCycle, milestone.totalMilestones, user_id],
          (err) => {
            if (err) {
              return res.status(500).json({ error: err.message });
            }
            
            // Registrar transacción
            db.run(
              `INSERT INTO rake_transactions (user_id, amount, bonus_released, description)
               VALUES (?, ?, ?, ?)`,
              [user_id, rakeAmount, bonusToRelease, description],
              function(err) {
                if (err) {
                  return res.status(500).json({ error: err.message });
                }
                
                // Verificar regalos condicionales
                checkConditionalGifts(user_id, 'rake', new_total_rake);
                
                res.json({
                  message: 'Rake agregado exitosamente',
                  rake_amount: rakeAmount,
                  bonus_released: bonusToRelease,
                  milestones_reached: milestone.newMilestones,
                  current_cycle: milestone.newRakeCycle,
                  next_milestone: RAKE_MILESTONE - milestone.newRakeCycle,
                  transaction_id: this.lastID,
                  active_bonus: activeBonus ? activeBonus.bonus_name : 'Principal'
                });
              }
            );
          }
        );
      }
    );
  });
});

// Obtener hitos de un usuario
app.get('/api/milestones/:userId', (req, res) => {
  const { userId } = req.params;
  
  db.all(
    'SELECT * FROM rake_milestones WHERE user_id = ? ORDER BY reached_at DESC',
    [userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
    }
  );
});

// ==================== NUEVAS RUTAS - BONOS MÚLTIPLES ====================

// Obtener bonos de un usuario
app.get('/api/user-bonuses/:userId', (req, res) => {
  const { userId } = req.params;
  
  db.all(
    'SELECT * FROM user_bonuses WHERE user_id = ? ORDER BY bonus_order',
    [userId],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(rows);
    }
  );
});

// Crear nuevo bono para usuario (admin)
app.post('/api/admin/user-bonuses', authenticateAdmin, (req, res) => {
  const { 
    user_id, 
    bonus_name, 
    bonus_amount, 
    bonus_type = 'deposit',
    activation_condition 
  } = req.body;

  // Obtener el siguiente orden
  db.get(
    'SELECT COUNT(*) + 1 as next_order FROM user_bonuses WHERE user_id = ?',
    [user_id],
    (err, result) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      const query = `
        INSERT INTO user_bonuses (
          user_id, bonus_name, bonus_amount, bonus_type, 
          bonus_order, activation_condition
        )
        VALUES (?, ?, ?, ?, ?, ?)
      `;

      db.run(query, [
        user_id, bonus_name, bonus_amount, bonus_type, 
        result.next_order, activation_condition
      ], function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        res.json({ 
          id: this.lastID, 
          message: 'Bono creado exitosamente' 
        });
      });
    }
  );
});

// Activar bono manualmente (admin)
app.put('/api/admin/user-bonuses/:id/activate', authenticateAdmin, (req, res) => {
  const { id } = req.params;

  // Verificar que el bono existe y está inactivo
  db.get('SELECT * FROM user_bonuses WHERE id = ?', [id], (err, bonus) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!bonus) {
      return res.status(404).json({ error: 'Bono no encontrado' });
    }
    if (bonus.status === 'active') {
      return res.status(400).json({ error: 'El bono ya está activo' });
    }
    if (bonus.status === 'completed') {
      return res.status(400).json({ error: 'El bono ya está completado' });
    }

    // Desactivar otros bonos activos del mismo usuario
    db.run(
      'UPDATE user_bonuses SET status = "inactive" WHERE user_id = ? AND status = "active"',
      [bonus.user_id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Activar el bono seleccionado
        db.run(
          'UPDATE user_bonuses SET status = "active", activated_at = CURRENT_TIMESTAMP WHERE id = ?',
          [id],
          (err) => {
            if (err) {
              return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Bono activado exitosamente' });
          }
        );
      }
    );
  });
});

// ==================== RUTAS REGALOS CONDICIONALES ====================

// Crear regalo condicional (admin)
app.post('/api/admin/conditional-gifts', authenticateAdmin, (req, res) => {
  const { 
    title, 
    description, 
    condition_type, 
    condition_value, 
    gift_type, 
    gift_value, 
    gift_title, 
    gift_description,
    is_global = true,
    specific_user_id,
    max_claims = 1
  } = req.body;

  const query = `
    INSERT INTO conditional_gifts (
      title, description, condition_type, condition_value,
      gift_type, gift_value, gift_title, gift_description,
      is_global, specific_user_id, max_claims
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(query, [
    title, description, condition_type, condition_value,
    gift_type, gift_value, gift_title, gift_description,
    is_global, specific_user_id, max_claims
  ], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ 
      id: this.lastID, 
      message: 'Regalo condicional creado exitosamente' 
    });
  });
});

// Obtener regalos condicionales disponibles para un usuario
app.get('/api/conditional-gifts/:userId', (req, res) => {
  const { userId } = req.params;
  
  const query = `
    SELECT cg.*, cgc.progress, cgc.is_claimed, cgc.claimed_at
    FROM conditional_gifts cg
    LEFT JOIN conditional_gift_claims cgc ON cg.id = cgc.conditional_gift_id AND cgc.user_id = ?
    WHERE cg.is_active = 1 AND (cg.is_global = 1 OR cg.specific_user_id = ?)
    ORDER BY cg.created_at DESC
  `;
  
  db.all(query, [userId, userId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Obtener todos los regalos condicionales (admin)
app.get('/api/admin/conditional-gifts', authenticateAdmin, (req, res) => {
  db.all('SELECT * FROM conditional_gifts ORDER BY created_at DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Toggle estado activo/inactivo de regalo condicional (admin)
app.put('/api/admin/conditional-gifts/:id/toggle', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  const { is_active } = req.body;

  db.run(
    'UPDATE conditional_gifts SET is_active = ? WHERE id = ?',
    [is_active ? 1 : 0, id],
    (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Estado actualizado exitosamente' });
    }
  );
});

// Eliminar regalo condicional (admin)
app.delete('/api/admin/conditional-gifts/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;

  db.run('DELETE FROM conditional_gifts WHERE id = ?', [id], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Regalo condicional eliminado exitosamente' });
  });
});

// Reclamar regalo condicional
app.put('/api/conditional-gifts/:id/claim', (req, res) => {
  const { id } = req.params;

  // Esta funcionalidad debería implementarse según la lógica de negocio
  res.json({ message: 'Funcionalidad de reclamación pendiente de implementar' });
});

// ==================== RUTAS DE REGALOS ====================

// Obtener regalos de un usuario
app.get('/api/gifts/:userId', (req, res) => {
  const { userId } = req.params;
  const { status } = req.query;

  let query = `
    SELECT g.*, u.username 
    FROM user_gifts g 
    JOIN users u ON g.user_id = u.id 
    WHERE g.user_id = ?
  `;
  let params = [userId];

  if (status) {
    query += ' AND g.status = ?';
    params.push(status);
  }

  query += ' ORDER BY g.created_at DESC';

  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Obtener todos los regalos (admin)
app.get('/api/admin/gifts', authenticateAdmin, (req, res) => {
  const { user_id, status } = req.query;

  let query = `
    SELECT g.*, u.username, u.email 
    FROM user_gifts g 
    JOIN users u ON g.user_id = u.id 
  `;
  let params = [];
  let conditions = [];

  if (user_id) {
    conditions.push('g.user_id = ?');
    params.push(user_id);
  }

  if (status) {
    conditions.push('g.status = ?');
    params.push(status);
  }

  if (conditions.length > 0) {
    query += 'WHERE ' + conditions.join(' AND ');
  }

  query += ' ORDER BY g.created_at DESC';

  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Crear regalo (admin)
app.post('/api/admin/gifts', authenticateAdmin, (req, res) => {
  const { 
    user_id, 
    gift_type, 
    gift_value, 
    title, 
    description 
  } = req.body;

  if (!user_id || !gift_type || !gift_value || !title) {
    return res.status(400).json({ error: 'Campos requeridos faltantes' });
  }

  const query = `
    INSERT INTO user_gifts (user_id, gift_type, gift_value, title, description, admin_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.run(query, [user_id, gift_type, gift_value, title, description, req.adminId], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Si es un bono, agregarlo automáticamente al usuario
    if (gift_type === 'bonus') {
      db.run(
        'UPDATE users SET bonus_amount = bonus_amount + ? WHERE id = ?',
        [gift_value, user_id],
        (err) => {
          if (err) {
            console.error('Error adding bonus to user:', err);
          }
        }
      );
    }

    res.json({ 
      id: this.lastID, 
      message: 'Regalo creado exitosamente' 
    });
  });
});

// Marcar regalo como reclamado
app.put('/api/gifts/:id/claim', (req, res) => {
  const { id } = req.params;

  db.run(
    `UPDATE user_gifts 
     SET status = 'claimed', claimed_at = CURRENT_TIMESTAMP 
     WHERE id = ?`,
    [id],
    (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Regalo reclamado exitosamente' });
    }
  );
});

// ==================== EDITAR USUARIOS Y BONOS ====================

// Actualizar datos completos de usuario (admin)
app.put('/api/admin/users/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  const { 
    username,
    email,
    phone,
    initial_deposit,
    bonus_amount,
    bonus_released,
    total_rake,
    current_rake_cycle,
    total_milestones,
    rakeback_percentage,
    status
  } = req.body;

  const query = `
    UPDATE users 
    SET username = ?, email = ?, phone = ?, initial_deposit = ?, 
        bonus_amount = ?, bonus_released = ?, total_rake = ?, 
        current_rake_cycle = ?, total_milestones = ?, 
        rakeback_percentage = ?, status = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `;

  db.run(query, [
    username, email, phone, initial_deposit,
    bonus_amount, bonus_released, total_rake,
    current_rake_cycle || 0, total_milestones || 0,
    rakeback_percentage, status, id
  ], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Usuario actualizado exitosamente' });
  });
});

// Ajustar bono específico (admin) - para correcciones rápidas
app.post('/api/admin/users/:id/adjust-bonus', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  const { adjustment_amount, reason } = req.body;

  // Obtener usuario actual
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const new_bonus_released = Math.max(0, user.bonus_released + parseFloat(adjustment_amount));
    const max_bonus = Math.min(new_bonus_released, user.bonus_amount);

    db.run(
      'UPDATE users SET bonus_released = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [max_bonus, id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Registrar el ajuste como transacción especial
        db.run(
          `INSERT INTO rake_transactions (user_id, amount, bonus_released, description)
           VALUES (?, ?, ?, ?)`,
          [id, 0, parseFloat(adjustment_amount), `Ajuste manual: ${reason}`],
          () => {
            res.json({ 
              message: 'Bono ajustado exitosamente',
              previous_bonus: user.bonus_released,
              new_bonus: max_bonus,
              adjustment: parseFloat(adjustment_amount)
            });
          }
        );
      }
    );
  });
});

// ==================== RUTAS DE METAS ====================

// Obtener metas de un usuario
app.get('/api/goals/:userId', (req, res) => {
  const { userId } = req.params;
  const { status } = req.query;

  let query = 'SELECT * FROM goals WHERE user_id = ?';
  let params = [userId];

  if (status) {
    query += ' AND status = ?';
    params.push(status);
  }

  query += ' ORDER BY created_at DESC';

  db.all(query, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Crear meta (admin)
app.post('/api/admin/goals', authenticateAdmin, (req, res) => {
  const { 
    user_id, 
    title, 
    description, 
    target_amount, 
    reward_amount, 
    reward_type = 'bonus',
    deadline 
  } = req.body;

  const query = `
    INSERT INTO goals (user_id, title, description, target_amount, reward_amount, reward_type, deadline)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.run(query, [user_id, title, description, target_amount, reward_amount, reward_type, deadline], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ 
      id: this.lastID, 
      message: 'Meta creada exitosamente' 
    });
  });
});

// Actualizar progreso de meta
app.put('/api/admin/goals/:id/progress', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  const { current_progress } = req.body;

  // Obtener la meta actual
  db.get('SELECT * FROM goals WHERE id = ?', [id], (err, goal) => {
    if (err || !goal) {
      return res.status(404).json({ error: 'Meta no encontrada' });
    }

    const newStatus = current_progress >= goal.target_amount ? 'completed' : 'active';
    const completedAt = newStatus === 'completed' ? new Date().toISOString() : null;

    db.run(
      `UPDATE goals 
       SET current_progress = ?, status = ?, completed_at = ?, updated_at = CURRENT_TIMESTAMP 
       WHERE id = ?`,
      [current_progress, newStatus, completedAt, id],
      (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Si se completó la meta, otorgar recompensa
        if (newStatus === 'completed' && goal.reward_amount > 0) {
          db.run(
            'UPDATE users SET bonus_amount = bonus_amount + ? WHERE id = ?',
            [goal.reward_amount, goal.user_id],
            () => {
              res.json({ 
                message: 'Meta completada y recompensa otorgada',
                reward_granted: goal.reward_amount
              });
            }
          );
        } else {
          res.json({ message: 'Progreso actualizado exitosamente' });
        }
      }
    );
  });
});

// ==================== ESTADÍSTICAS MEJORADAS ====================
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
  const stats = {};
  
  // Estadísticas existentes...
  db.get("SELECT COUNT(*) as total FROM news", (err, row) => {
    stats.totalNews = row?.total || 0;
    
    db.get("SELECT COUNT(*) as total FROM users", (err, row) => {
      stats.totalUsers = row?.total || 0;
      
      db.get("SELECT SUM(total_rake) as total FROM users", (err, row) => {
        stats.totalRake = row?.total || 0;
        
        db.get("SELECT SUM(bonus_released) as total FROM users", (err, row) => {
          stats.totalBonusReleased = row?.total || 0;
          
          // Estadísticas de metas
          db.get("SELECT COUNT(*) as total FROM goals WHERE status = 'active'", (err, row) => {
            stats.activeGoals = row?.total || 0;
            
            db.get("SELECT SUM(total_milestones) as total FROM users", (err, row) => {
              stats.totalMilestones = row?.total || 0;
              
              // Estadísticas de regalos
              db.get("SELECT COUNT(*) as total FROM user_gifts WHERE status = 'active'", (err, row) => {
                stats.activeGifts = row?.total || 0;
                
                db.get("SELECT SUM(gift_value) as total FROM user_gifts WHERE gift_type = 'bonus'", (err, row) => {
                  stats.totalGiftBonuses = row?.total || 0;
                  
                  // NUEVAS ESTADÍSTICAS
                  db.get("SELECT COUNT(*) as total FROM conditional_gifts WHERE is_active = 1", (err, row) => {
                    stats.activeConditionalGifts = row?.total || 0;
                    
                    db.get("SELECT COUNT(*) as total FROM user_bonuses WHERE status = 'active'", (err, row) => {
                      stats.activeBonuses = row?.total || 0;
                      
                      db.get("SELECT COUNT(*) as total FROM user_bonuses WHERE status = 'completed'", (err, row) => {
                        stats.completedBonuses = row?.total || 0;
                        
                        db.all("SELECT title, views FROM news ORDER BY views DESC LIMIT 5", (err, topNews) => {
                          stats.topNews = topNews || [];
                          
                          res.json(stats);
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

// Endpoint de estadísticas mejoradas (nuevo)
app.get('/api/admin/stats-improved', authenticateAdmin, (req, res) => {
  const stats = {};
  
  // Estadísticas existentes
  db.get("SELECT COUNT(*) as total FROM news", (err, row) => {
    stats.totalNews = row?.total || 0;
    
    db.get("SELECT COUNT(*) as total FROM users", (err, row) => {
      stats.totalUsers = row?.total || 0;
      
      db.get("SELECT SUM(total_rake) as total FROM users", (err, row) => {
        stats.totalRake = row?.total || 0;
        
        db.get("SELECT SUM(bonus_released) as total FROM users", (err, row) => {
          stats.totalBonusReleased = row?.total || 0;
          
          // Nuevas estadísticas
          db.get("SELECT COUNT(*) as total FROM conditional_gifts WHERE is_active = 1", (err, row) => {
            stats.activeConditionalGifts = row?.total || 0;
            
            db.get("SELECT COUNT(*) as total FROM user_bonuses WHERE status = 'active'", (err, row) => {
              stats.activeBonuses = row?.total || 0;
              
              db.get("SELECT COUNT(*) as total FROM user_bonuses WHERE status = 'completed'", (err, row) => {
                stats.completedBonuses = row?.total || 0;
                
                db.get("SELECT COUNT(*) as total FROM goals WHERE status = 'active'", (err, row) => {
                  stats.activeGoals = row?.total || 0;
                  
                  db.get("SELECT COUNT(*) as total FROM user_gifts WHERE status = 'active'", (err, row) => {
                    stats.activeGifts = row?.total || 0;
                    
                    db.get("SELECT SUM(total_milestones) as total FROM users", (err, row) => {
                      stats.totalMilestones = row?.total || 0;
                      
                      db.all("SELECT title, views FROM news ORDER BY views DESC LIMIT 5", (err, topNews) => {
                        stats.topNews = topNews || [];
                        
                        res.json(stats);
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

// ==================== RUTA DE TEST ====================
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'API funcionando correctamente',
    uploadsPath: path.join(__dirname, 'uploads'),
    newsPath: path.join(__dirname, 'uploads', 'news'),
    version: '4.0 - Completa con Bonos Múltiples, Regalos Condicionales y Búsqueda',
    features: [
      'Editor Enriquecido',
      'Sistema de Galería',
      'HTML Enriquecido',
      'Sistema de Regalos',
      'Sistema de Metas',
      'Edición de Usuarios',
      'Sistema de Rake con Hitos',
      'Bonos Múltiples', // NUEVO
      'Regalos Condicionales', // NUEVO
      'Búsqueda de Usuarios', // NUEVO
      'Rake Mejorado con Bonos', // NUEVO
      'Estadísticas Avanzadas'
    ]
  });
});

// Ruta para verificar si una imagen existe
app.get('/api/test-image/:filename', (req, res) => {
  const imagePath = path.join(__dirname, 'uploads', 'news', req.params.filename);
  if (fs.existsSync(imagePath)) {
    res.json({ exists: true, path: imagePath });
  } else {
    res.status(404).json({ exists: false, path: imagePath });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 Server running on port ${PORT}`);
  console.log(`📧 Admin credentials: ${process.env.ADMIN_EMAIL || 'admin@pokerprotrack.com'}`);
  console.log(`📁 Uploads directory: ${path.join(__dirname, 'uploads')}`);
  console.log(`🌐 Static files served at: http://localhost:${PORT}/uploads/`);
  console.log(`\n✨ FUNCIONALIDADES ACTIVAS:`);
  console.log(`   📝 Editor Enriquecido: Activado`);
  console.log(`   📸 Soporte de Galería: Activado`);
  console.log(`   🎯 Sistema de Metas: Activado`);
  console.log(`   🎁 Sistema de Regalos: Activado`);
  console.log(`   ✏️ Edición de Usuarios: Activado`);
  console.log(`   🏆 Sistema de Rake con Hitos: Activado`);
  console.log(`   💰 Bonos Múltiples: Activado`); // NUEVO
  console.log(`   🎭 Regalos Condicionales: Activado`); // NUEVO
  console.log(`   🔍 Búsqueda de Usuarios: Activado`); // NUEVO
  console.log(`   📊 Estadísticas Avanzadas: Activado`);
  console.log(`\n📊 RAKE SYSTEM CONFIG:`);
  console.log(`   🎯 Milestone: ${RAKE_MILESTONE} soles`);
  console.log(`   💰 Bonus per milestone: ${MILESTONE_BONUS} soles\n`);
});