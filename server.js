const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/ws" });

const PORT = 4000;
const JWT_SECRET = "super_secreto_change_me"; // cámbialo en producción

//app.use(express.json());
//app.use(cors({
//  origin: ["http://localhost", "http://localhost:8001", "http://localhost:5173", "http://localhost:5174"],
//  credentials: true
//}));

// prueba git


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: ["http://chat.hginet.com.co:8001"], // solo el front en prod
  credentials: true
}));



const fs = require('fs');
const path = require('path');
const multer = require('multer');

// Configuración de Multer
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    // Evitar colisiones de nombres
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Middleware de logging para debugging
app.use((req, res, next) => {
  if (req.path.startsWith("/api/rooms") && (req.method === "PUT" || req.method === "DELETE")) {
    console.log(`${req.method} ${req.path}`, {
      params: req.params,
      body: req.body,
      hasAuth: !!req.headers.authorization
    });
  }
  next();
});

// Servir archivos estáticos (uploads)
app.use('/uploads', express.static(uploadDir));

// Ruta de subida de archivos
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No se subió ningún archivo" });
  }
  // Devolver URL relativa
  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({
    url: fileUrl,
    type: req.file.mimetype,
    name: req.file.originalname
  });
});

// ==============================
// Helpers de autenticación
// ==============================

function generarToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "8h" }
  );
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Sin token" });

  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// ==============================
// Rutas REST: Registro y Login
// ==============================

app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Usuario y contraseña son obligatorios" });

  const password_hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    [username, password_hash],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(400).json({ error: "Usuario ya existe o error en BD" });
      }
      const user = { id: this.lastID, username };
      const token = generarToken(user);
      return res.json({ user, token });
    }
  );
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Usuario y contraseña son obligatorios" });

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Error en BD" });
    }
    if (!row) return res.status(401).json({ error: "Usuario o contraseña inválidos" });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: "Usuario o contraseña inválidos" });

    const user = { id: row.id, username: row.username };
    const token = generarToken(user);
    return res.json({ user, token });
  });
});

// ==============================
// Rutas REST: Usuarios y mensajes 1 a 1
// ==============================

// Lista de usuarios (para mostrar quién existe y su estado online se maneja en WS)
app.get("/api/users", authMiddleware, (req, res) => {
  db.all("SELECT id, username FROM users", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error en BD" });

    // Inyectar estado online basado en conexiones activas
    const onlineIds = Array.from(clients.keys());
    const usersWithStatus = rows.map(u => ({
      ...u,
      online: onlineIds.includes(u.id)
    }));

    res.json(usersWithStatus);
  });
});

// Historial de mensajes privados entre el usuario logueado y otro usuario
app.get("/api/messages/:otherUserId", authMiddleware, (req, res) => {
  const userId = req.user.id;
  const otherUserId = parseInt(req.params.otherUserId, 10);

  const sql = `
    SELECT id, from_user_id, to_user_id, content, file_url, file_type, created_at
    FROM messages
    WHERE (from_user_id = ? AND to_user_id = ?)
       OR (from_user_id = ? AND to_user_id = ?)
    ORDER BY created_at ASC
  `;
  db.all(sql, [userId, otherUserId, otherUserId, userId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error en BD" });
    res.json(rows);
  });
});

// ==============================
// Rutas REST: Salas / grupos
// ==============================

// Listar salas donde está el usuario
app.get("/api/rooms", authMiddleware, (req, res) => {
  const userId = req.user.id;
  const sql = `
    SELECT r.id, r.name
    FROM rooms r
    INNER JOIN room_members rm ON rm.room_id = r.id
    WHERE rm.user_id = ?
    ORDER BY r.name
  `;
  db.all(sql, [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error en BD" });
    res.json(rows);
  });
});

// Crear sala (incluye al creador y, opcionalmente, otros miembros)
app.post("/api/rooms", authMiddleware, (req, res) => {
  const { name, memberIds } = req.body;
  const userId = req.user.id;

  if (!name) return res.status(400).json({ error: "Nombre requerido" });

  // siempre incluir al creador
  const members = new Set([userId, ...(memberIds || [])]);

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");
    db.run(
      "INSERT INTO rooms (name) VALUES (?)",
      [name],
      function (err) {
        if (err) {
          console.error(err);
          db.run("ROLLBACK");
          return res.status(500).json({ error: "Error creando sala" });
        }
        const roomId = this.lastID;

        let errorEnMiembros = false;
        const insertMember = db.prepare(
          "INSERT OR IGNORE INTO room_members (room_id, user_id) VALUES (?, ?)"
        );

        for (const m of members) {
          insertMember.run(roomId, m, (err2) => {
            if (err2) {
              console.error(err2);
              errorEnMiembros = true;
            }
          });
        }

        insertMember.finalize((err3) => {
          if (err3 || errorEnMiembros) {
            console.error(err3);
            db.run("ROLLBACK");
            return res.status(500).json({ error: "Error agregando miembros" });
          }
          db.run("COMMIT");
          return res.json({ id: roomId, name });
        });
      }
    );
  });
});

// Historial de mensajes de una sala
app.get("/api/rooms/:roomId/messages", authMiddleware, (req, res) => {
  const roomId = parseInt(req.params.roomId, 10);
  const sql = `
    SELECT 
      rm.id, 
      rm.room_id, 
      rm.from_user_id, 
      rm.content, 
      rm.file_url,
      rm.file_type,
      rm.created_at,
      u.username as from_username
    FROM room_messages rm
    INNER JOIN users u ON rm.from_user_id = u.id
    WHERE rm.room_id = ?
    ORDER BY rm.created_at ASC
  `;
  db.all(sql, [roomId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error en BD" });
    res.json(rows);
  });
});

// Obtener miembros de una sala
app.get("/api/rooms/:roomId/members", authMiddleware, (req, res) => {
  const roomId = parseInt(req.params.roomId, 10);
  const sql = `
    SELECT u.id, u.username
    FROM room_members rm
    INNER JOIN users u ON rm.user_id = u.id
    WHERE rm.room_id = ?
    ORDER BY u.username
  `;
  db.all(sql, [roomId], (err, rows) => {
    if (err) return res.status(500).json({ error: "Error en BD" });
    res.json(rows);
  });
});

// Eliminar una sala
app.delete("/api/rooms/:roomId", authMiddleware, (req, res) => {
  const roomId = parseInt(req.params.roomId, 10);
  const userId = req.user.id;

  // Verificar que el usuario es miembro de la sala
  db.get("SELECT * FROM room_members WHERE room_id = ? AND user_id = ?", [roomId, userId], (err, row) => {
    if (err) {
      console.error("Error verificando membresía:", err);
      return res.status(500).json({ error: "Error en BD" });
    }
    if (!row) {
      return res.status(403).json({ error: "No eres miembro de esta sala" });
    }

    db.serialize(() => {
      db.run("BEGIN TRANSACTION", (beginErr) => {
        if (beginErr) {
          console.error("Error iniciando transacción:", beginErr);
          return res.status(500).json({ error: "Error iniciando transacción" });
        }

        // Eliminar mensajes de la sala
        db.run("DELETE FROM room_messages WHERE room_id = ?", [roomId], (err1) => {
          if (err1) {
            console.error("Error eliminando mensajes:", err1);
            db.run("ROLLBACK");
            return res.status(500).json({ error: "Error eliminando mensajes" });
          }

          // Eliminar miembros de la sala
          db.run("DELETE FROM room_members WHERE room_id = ?", [roomId], (err2) => {
            if (err2) {
              console.error("Error eliminando miembros:", err2);
              db.run("ROLLBACK");
              return res.status(500).json({ error: "Error eliminando miembros" });
            }

            // Eliminar la sala
            db.run("DELETE FROM rooms WHERE id = ?", [roomId], (err3) => {
              if (err3) {
                console.error("Error eliminando sala:", err3);
                db.run("ROLLBACK");
                return res.status(500).json({ error: "Error eliminando sala" });
              }

              db.run("COMMIT", (commitErr) => {
                if (commitErr) {
                  console.error("Error en commit:", commitErr);
                  return res.status(500).json({ error: "Error en commit" });
                }
                return res.json({ success: true, message: "Sala eliminada correctamente" });
              });
            });
          });
        });
      });
    });
  });
});

// Actualizar miembros de una sala
app.put("/api/rooms/:roomId/members", authMiddleware, (req, res) => {
  console.log("PUT /api/rooms/:roomId/members llamado", req.params.roomId, req.body);
  const roomId = parseInt(req.params.roomId, 10);
  const { memberIds } = req.body;
  const userId = req.user.id;

  if (!Array.isArray(memberIds)) {
    return res.status(400).json({ error: "memberIds debe ser un array" });
  }

  // Verificar que el usuario es miembro de la sala
  db.get("SELECT * FROM room_members WHERE room_id = ? AND user_id = ?", [roomId, userId], (err, row) => {
    if (err) {
      console.error("Error verificando membresía:", err);
      return res.status(500).json({ error: "Error en BD" });
    }
    if (!row) {
      return res.status(403).json({ error: "No eres miembro de esta sala" });
    }

    // Siempre incluir al usuario actual
    const miembrosFinales = Array.from(new Set([userId, ...memberIds]));
    console.log("Miembros finales a insertar:", miembrosFinales);

    db.serialize(() => {
      db.run("BEGIN TRANSACTION");

      // Eliminar todos los miembros actuales
      db.run("DELETE FROM room_members WHERE room_id = ?", [roomId], function (deleteErr) {
        if (deleteErr) {
          console.error("Error eliminando miembros:", deleteErr);
          db.run("ROLLBACK");
          return res.status(500).json({ error: "Error eliminando miembros" });
        }

        if (miembrosFinales.length === 0) {
          db.run("COMMIT", (commitErr) => {
            if (commitErr) {
              console.error("Error en commit:", commitErr);
              return res.status(500).json({ error: "Error en commit" });
            }
            return res.json({ success: true, members: [] });
          });
          return;
        }

        // Insertar los nuevos miembros usando un prepared statement
        const stmt = db.prepare("INSERT INTO room_members (room_id, user_id) VALUES (?, ?)");
        let completados = 0;
        let errorOcurrido = false;

        for (const memberId of miembrosFinales) {
          stmt.run([roomId, memberId], function (insertErr) {
            completados++;

            if (insertErr) {
              console.error(`Error insertando miembro ${memberId}:`, insertErr);
              errorOcurrido = true;
            }

            // Cuando todos los inserts terminen
            if (completados === miembrosFinales.length) {
              stmt.finalize((finalizeErr) => {
                if (finalizeErr) {
                  console.error("Error finalizando statement:", finalizeErr);
                  errorOcurrido = true;
                }

                if (errorOcurrido) {
                  db.run("ROLLBACK");
                  return res.status(500).json({ error: "Error agregando algunos miembros" });
                }

                db.run("COMMIT", (commitErr) => {
                  if (commitErr) {
                    console.error("Error en commit:", commitErr);
                    return res.status(500).json({ error: "Error en commit" });
                  }
                  console.log("Miembros actualizados exitosamente:", miembrosFinales);
                  return res.json({ success: true, members: miembrosFinales });
                });
              });
            }
          });
        }
      });
    });
  });
});

// ==============================
// WebSocket: tiempo real
// ==============================

// userId -> ws
const clients = new Map();

// Enviar lista de usuarios con flag online/offline a todos los conectados
function broadcastUserList() {
  db.all("SELECT id, username FROM users", [], (err, users) => {
    if (err) {
      console.error("Error leyendo usuarios:", err);
      return;
    }

    const onlineIds = Array.from(clients.keys());

    const payload = JSON.stringify({
      type: "USER_LIST",
      users: users.map(u => ({
        id: u.id,
        username: u.username,
        online: onlineIds.includes(u.id)
      }))
    });

    for (const ws of clients.values()) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
      }
    }
  });
}

// Manejo de conexiones WebSocket
wss.on("connection", (ws, req) => {
  // token en query: ws://localhost:4000/ws?token=...
  const params = new URLSearchParams(req.url.replace("/ws?", ""));
  const token = params.get("token");

  if (!token) {
    ws.send(JSON.stringify({ type: "ERROR", message: "Sin token" }));
    ws.close();
    return;
  }

  let user;
  try {
    user = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    ws.send(JSON.stringify({ type: "ERROR", message: "Token inválido" }));
    ws.close();
    return;
  }

  const userId = user.id;
  console.log("🔌 Usuario conectado WS:", user.username);

  clients.set(userId, ws);
  broadcastUserList();

  ws.on("message", (msg) => {
    try {
      const data = JSON.parse(msg.toString());

      // 📨 Mensaje privado 1 a 1
      if (data.type === "MESSAGE") {
        const { toUserId, content, fileUrl, fileType } = data;
        if ((!content && !fileUrl) || !toUserId) return;

        const finalContent = content || ""; // Permitir contenido vacío si hay archivo

        db.run(
          "INSERT INTO messages (from_user_id, to_user_id, content, file_url, file_type) VALUES (?, ?, ?, ?, ?)",
          [userId, toUserId, finalContent, fileUrl, fileType],
          function (err) {
            if (err) {
              console.error("Error guardando mensaje:", err);
              return;
            }

            const messageObj = {
              id: this.lastID,
              from_user_id: userId,
              to_user_id: toUserId,
              content: finalContent,
              file_url: fileUrl,
              file_type: fileType,
              created_at: new Date().toISOString()
            };

            const payload = JSON.stringify({
              type: "MESSAGE",
              message: messageObj
            });

            const wsFrom = clients.get(userId);
            if (wsFrom && wsFrom.readyState === WebSocket.OPEN) {
              wsFrom.send(payload);
            }

            const wsTo = clients.get(toUserId);
            if (wsTo && wsTo.readyState === WebSocket.OPEN) {
              wsTo.send(payload);
            }
          }
        );
      }

      // 🏠 Mensaje a sala/grupo
      if (data.type === "ROOM_MESSAGE") {
        const { roomId, content, fileUrl, fileType } = data;
        if (!roomId || (!content && !fileUrl)) return;

        const finalContent = content || "";

        db.run(
          "INSERT INTO room_messages (room_id, from_user_id, content, file_url, file_type) VALUES (?, ?, ?, ?, ?)",
          [roomId, userId, finalContent, fileUrl, fileType],
          function (err) {
            if (err) {
              console.error("Error guardando mensaje de sala:", err);
              return;
            }

            // Obtener el username del remitente
            db.get("SELECT username FROM users WHERE id = ?", [userId], (errUser, userRow) => {
              if (errUser) {
                console.error("Error obteniendo username:", errUser);
                return;
              }

              const messageObj = {
                id: this.lastID,
                room_id: roomId,
                from_user_id: userId,
                from_username: userRow ? userRow.username : "Usuario",
                content: finalContent,
                file_url: fileUrl,
                file_type: fileType,
                created_at: new Date().toISOString()
              };

              const payload = JSON.stringify({
                type: "ROOM_MESSAGE",
                message: messageObj
              });

              // Obtener miembros de la sala y enviarles el mensaje
              db.all(
                "SELECT user_id FROM room_members WHERE room_id = ?",
                [roomId],
                (err2, rows) => {
                  if (err2) {
                    console.error("Error leyendo miembros de sala:", err2);
                    return;
                  }

                  rows.forEach(r => {
                    const wsClient = clients.get(r.user_id);
                    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
                      wsClient.send(payload);
                    }
                  });
                }
              );
            });
          }
        );
      }

      // ✏️ Indicador "escribiendo..." en chat privado
      if (data.type === "TYPING") {
        const { toUserId, isTyping } = data;
        const wsTo = clients.get(toUserId);
        if (wsTo && wsTo.readyState === WebSocket.OPEN) {
          wsTo.send(JSON.stringify({
            type: "TYPING",
            fromUserId: userId,
            isTyping
          }));
        }
      }

      // ✏️ Indicador "escribiendo..." en sala
      if (data.type === "TYPING_ROOM") {
        const { roomId, isTyping } = data;
        db.all(
          "SELECT user_id FROM room_members WHERE room_id = ?",
          [roomId],
          (err2, rows) => {
            if (err2) {
              console.error("Error leyendo miembros de sala:", err2);
              return;
            }

            rows.forEach(r => {
              if (r.user_id === userId) return; // no se lo mando a sí mismo
              const wsClient = clients.get(r.user_id);
              if (wsClient && wsClient.readyState === WebSocket.OPEN) {
                wsClient.send(JSON.stringify({
                  type: "TYPING_ROOM",
                  fromUserId: userId,
                  roomId,
                  isTyping
                }));
              }
            });
          }
        );
      }

      // ==========================
      // Señalización WebRTC (voz / video / pantalla / dataChannel)
      // ==========================
      if (
        data.type === "RTC_CALL_OFFER" ||
        data.type === "RTC_CALL_ANSWER" ||
        data.type === "RTC_ICE_CANDIDATE" ||
        data.type === "RTC_CALL_END" ||
        data.type === "RTC_DATA"
      ) {
        const { toUserId } = data;
        if (!toUserId) return;

        const wsTarget = clients.get(toUserId);
        if (wsTarget && wsTarget.readyState === WebSocket.OPEN) {
          wsTarget.send(
            JSON.stringify({
              ...data,
              fromUserId: userId, // siempre indicar quién envía
            })
          );
        }
      }


    } catch (e) {
      console.error("Error procesando mensaje WS", e);
    }
  });

  ws.on("close", () => {
    console.log("❌ Usuario desconectado WS:", user.username);
    clients.delete(userId);
    broadcastUserList();
  });
});

// server.listen(PORT, () => {
//   console.log(`🚀 Backend escuchando en http://localhost:${PORT}`);
// });


server.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Backend escuchando en http://0.0.0.0:${PORT}`);
});
