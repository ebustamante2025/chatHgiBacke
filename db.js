const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Ruta al archivo de base de datos SQLite
const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);

// Crear tablas si no existen
db.serialize(() => {
  // Usuarios
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    )
  `);

  // Mensajes privados 1 a 1
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user_id INTEGER NOT NULL,
      to_user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      file_url TEXT,
      file_type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (from_user_id) REFERENCES users(id),
      FOREIGN KEY (to_user_id) REFERENCES users(id)
    )
  `);

  // Salas / grupos
  db.run(`
    CREATE TABLE IF NOT EXISTS rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL
    )
  `);

  // Miembros de las salas
  db.run(`
    CREATE TABLE IF NOT EXISTS room_members (
      room_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY (room_id, user_id),
      FOREIGN KEY (room_id) REFERENCES rooms(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Mensajes de salas
  db.run(`
    CREATE TABLE IF NOT EXISTS room_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id INTEGER NOT NULL,
      from_user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      file_url TEXT,
      file_type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (room_id) REFERENCES rooms(id),
      FOREIGN KEY (from_user_id) REFERENCES users(id)
    )
  `);

  // Migraciones para bases de datos existentes
  const addColumn = (table, column, type) => {
    db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`, (err) => {
      // Ignorar error si la columna ya existe
      if (err && !err.message.includes("duplicate column name")) {
        console.error(`Error agregando columna ${column} a ${table}:`, err);
      }
    });
  };

  addColumn("messages", "file_url", "TEXT");
  addColumn("messages", "file_type", "TEXT");
  addColumn("room_messages", "file_url", "TEXT");
  addColumn("room_messages", "file_type", "TEXT");
});

module.exports = db;
