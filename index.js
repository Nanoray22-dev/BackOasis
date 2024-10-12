const express = require("express");
// const mongoose = require("mongoose");
// const { Sequelize, DataTypes } = require("sequelize");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const ws = require("ws");
const fs = require("fs");
const multer = require("multer");
const path = require("path");
const bodyParser = require("body-parser");
const socketIo = require("socket.io");
const { Resend } = require("resend");
const User = require("./Models/User");
const Message = require("./Models/Message");
// const Report = require('./Models/Report');
// const Comment = require('./Models/Comments');
const { Report, Comment } = require('./Models/associations');
const { Sequelize } = require("sequelize");
const { format } = require("date-fns");

dotenv.config();
// Configuración de Sequelize para SQL Server
const sequelize = new Sequelize(process.env.SQL_DATABASE, process.env.SQL_USER, process.env.SQL_PASSWORD, {
  host: process.env.SQL_HOST,
  dialect: 'mssql',
  port: process.env.SQL_PORT || 1433,
  logging: false,
  dialectOptions: {
    options: {
      encrypt: true,
    },
  },
});

// Probar la conexión a la base de datos
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Conexión exitosa a SQL Server');
  } catch (error) {
    console.error('Error de conexión a SQL Server:', error);
  }
})();

// Sincronizar los modelos
// Probar la conexión y sincronizar los modelos
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Conexión a la base de datos exitosa');
    
    // Sincronizar los modelos, crea las tablas si no existen
    await sequelize.sync({ force: true });  // Cambia a `force: true` para recrear tablas
    console.log('Tablas sincronizadas correctamente');
  } catch (error) {
    console.error('Error al sincronizar los modelos:', error);
  }
})();

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);
const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
app.use(bodyParser.json());
app.use("/uploads", express.static(path.join(__dirname, "/uploads")));
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = ["http://localhost:5173"];
app.use(cors({
  credentials: true,
  origin: function (origin, callback) {
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
}));

const server = app.listen(process.env.PORT);
const io = socketIo(server);

const authenticateJWT = async (req, res, next) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findByPk(decodedToken.userId);  // Attach the user to the request

    if (!req.user) {
      return res.status(401).json({ error: "User not found" });
    }

    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return res.status(401).json({ error: "Authentication failed" });
  }
};

// Helper para obtener los datos del usuario desde la solicitud
async function getUserDataFromRequest(req) {
  return new Promise((resolve, reject) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, process.env.JWT_SECRET, (err, userData) => {
        if (err) {
          console.error("Error verifying token:", err);
          reject(new Error("Invalid token"));
        }
        resolve(userData);
      });
    } else {
      reject(new Error("No token provided"));
    }
  });
}

// Routes
app.get("/", (req, res) => res.json("test ok"));

app.get("/messages/:userId", async (req, res) => {
  const { userId } = req.params;
  const userData = await getUserDataFromRequest(req);
  const ourUserId = userData.userId;
  const messages = await Message.findAll({
    sender: { $in: [userId, ourUserId] },
    recipient: { $in: [userId, ourUserId] },
  }).sort({ createdAt: 1 });
  res.json(messages);
});

app.get("/people", async (req, res) => {
  const users = await User.findAll({}, { _id: 1, username: 1 });
  res.json(users);
});

app.get("/profile", (req, res) => {
  const token = req.cookies?.token;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, userData) => {
      if (err) throw err;
      res.json(userData);
    });
  } else {
    res.status(401).json("No se ha proporcionado token");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const foundUser = await User.findOne({ where: { username } });  // SQL Server query
    if (!foundUser) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const passOk = bcrypt.compareSync(password, foundUser.password);
    if (passOk) {
      jwt.sign(
        { userId: foundUser.id, username, role: foundUser.role },  // Using `id` instead of `_id`
        jwtSecret,
        {},
        (err, token) => {
          if (err) return res.status(500).json({ message: "Error en la generación del token" });
          
          res.cookie("token", token, { sameSite: "none", secure: true }).json({
            id: foundUser.id,  // Using `id` for SQL Server
            role: foundUser.role,
          });
        }
      );
    } else {
      res.status(401).json({ message: "Credenciales incorrectas" });
    }
  } catch (err) {
    res.status(500).json({ message: "Error en el servidor", error: err.message });
  }
});


app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    // Generar hash de la contraseña
    const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
    
    // Crear el usuario en la base de datos
    const createdUser = await User.create({
      username: username,
      password: hashedPassword,
    });
    
    // Generar token JWT
    jwt.sign(
      { userId: createdUser.id, username }, // Usar 'id' en lugar de '_id'
      jwtSecret,
      {},
      (err, token) => {
        if (err) {
          res.status(500).json({ message: "Error en la generación del token" });
        } else {
          // Enviar token en la cookie y devolver el id del usuario
          res
            .cookie("token", token, { sameSite: "none", secure: true })
            .status(201)
            .json({
              id: createdUser.id,  // Usar 'id' en lugar de '_id'
            });
        }
      }
    );
  } catch (err) {
    res.status(500).json({ message: "Error al registrar el usuario", error: err.message });
  }
});

app.post("/logout", (req, res) => {
  res.cookie("token", "", { sameSite: "none", secure: true }).json("ok");
});

// WebSocket setup
const wss = new ws.WebSocketServer({ server });

wss.on("connection", (socket) => {
  socket.on("close", () => {
    console.log("Cliente desconectado");
  });
});

const notifyAllClients = (message) => {
  wss.clients.forEach((client) => {
    if (client.readyState === ws.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
};

// Funcionalidades de WebSocket y manejo de mensajes
wss.on("connection", (connection, req) => {
  function notifyAboutOnlinePeople() {
    [...wss.clients].forEach((client) => {
      client.send(
        JSON.stringify({
          online: [...wss.clients].map((c) => ({
            userId: c.userId,
            username: c.username,
          })),
        })
      );
    });
  }

  connection.isAlive = true;

  connection.timer = setInterval(() => {
    connection.ping();
    connection.deathTimer = setTimeout(() => {
      connection.isAlive = false;
      clearInterval(connection.timer);
      connection.terminate();
      notifyAboutOnlinePeople();
    }, 1000);
  }, 5000);

  connection.on("pong", () => {
    clearTimeout(connection.deathTimer);
  });

  const cookies = req.headers.cookie;
  if (cookies) {
    const tokenCookieString = cookies.split(";").findAll((str) => str.startsWith("token="));
    if (tokenCookieString) {
      const token = tokenCookieString.split("=")[1];
      if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
          if (err) throw err;
          const { userId, username } = userData;
          connection.userId = userId;
          connection.username = username;
        });
      }
    }
  }

  connection.on("message", async (message) => {
    const messageData = JSON.parse(message.toString());
    const { recipient, text, file } = messageData;
    let filename = null;
    if (file) {
      const parts = file.name.split(".");
      const ext = parts[parts.length - 1];
      filename = Date.now() + "." + ext;
      const filePath = path.join(__dirname, "/uploads/", filename);
      const bufferData = Buffer.from(file.data.split(",")[1], "base64");
      fs.writeFile(filePath, bufferData, () => {
        console.log("Archivo guardado:" + filePath);
      });
    }
    if (recipient && (text || file)) {
      const messageDoc = await Message.create({
        sender: connection.userId,
        recipient,
        text,
        file: file ? filename : null,
      });
      [...wss.clients]
        .filter((c) => c.userId === recipient)
        .forEach((c) =>
          c.send(
            JSON.stringify({
              text,
              sender: connection.userId,
              recipient,
              file: file ? filename : null,
              _id: messageDoc._id,
            })
          )
        );
    }
  });

  notifyAboutOnlinePeople();
});


// Report handling setup
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, `${file.originalname}`);
  },
});

const upload = multer({ storage: storage });
const baseUrl = process.env.BASE_URL || 'http://localhost:4040';

// app.post("/report", upload.array("image"), async (req, res) => {
//   try {
//     const { title, description, state, incidentDate } = req.body;
//     let imagePaths = [];

//     if (req.files) {
//       imagePaths = req.files.map((file) => file.path);
//     }

//     console.log("Incoming data:", { title, description, state, incidentDate, imagePaths });

//     const token = req.cookies?.token;
//     if (!token) {
//       return res.status(401).json({ error: "User not authenticated" });
//     }

//     const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
//     const userId = decodedToken.userId;

//     // Ensure the date is formatted properly (YYYY-MM-DD)
//     const formattedIncidentDate = new Date(incidentDate).toISOString().slice(0, 10); // 'YYYY-MM-DD'

//     // Create the new report
//     const newReport = await Report.create({
//       title: title.trim(),
//       description: description.trim(),
//       state,
//       image: imagePaths,
//       incidentDate: formattedIncidentDate,  // Use formatted date here
//       createdBy: userId,
//     });

//     const reportWithDetails = {
//       ...newReport.toJSON(),
//       createdBy: (await User.findByPk(userId)).username,
//       images: imagePaths.map((path) => `${baseUrl}/${path}`),
//     };

//     res.status(201).json(reportWithDetails);
//   } catch (error) {
//     console.error("Error creating report:", error);
//     res.status(500).json({ error: "Error creating report" });
//   }
// });

 // Para formato de fecha más confiable

app.post('/report', upload.array('image'), async (req, res) => {
  try {
    const { title, description, state, incidentDate, imagePaths } = req.body;

    // Validar los campos
    if (!title || !description || !incidentDate) {
      return res.status(400).json({ error: 'Missing required fields: title, description, incidentDate' });
    }

    // Parsear la fecha y asegurar que esté en el formato correcto
    const parsedDate = new Date(incidentDate);
    if (isNaN(parsedDate.getTime())) {
      return res.status(400).json({ error: 'Invalid date format' });
    }

    const formattedIncidentDate = format(parsedDate, 'yyyy-MM-dd HH:mm:ss'); // Formato compatible con SQL Server

    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    // Log de datos para revisar qué estamos enviando
    console.log("Incoming data:", {
      title,
      description,
      state,
      formattedIncidentDate,
      imagePaths,
      createdBy: userId,
    });

    // Crear el reporte, asegurándonos que las imágenes se guarden como JSON válido
    const newReport = await Report.create({
      title: title.trim(),
      description: description.trim(),
      state,
      image: JSON.stringify(imagePaths),  // Almacenar las imágenes como JSON
      incidentDate: formattedIncidentDate, // Usar fecha formateada
      createdBy: userId,
      createdAt: Sequelize.fn('GETDATE'),  // Current timestamp
      updatedAt: Sequelize.fn('GETDATE')   // Current timestamp
    });

    res.status(201).json(newReport);

  } catch (error) {
    console.error('Error creating report:', error);
    res.status(500).json({ error: 'Error creating report' });
  }
});



app.get("/report", async (req, res) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let reports;
    const baseUrl = process.env.BASE_URL || 'http://localhost:4040';

    // If the user is an admin, fetch all reports; otherwise, fetch only reports created by the user
    if (user.role === "admin") {
      reports = await Report.findAll({
        include: [
          {
            model: User,
            as: 'creator',  // Include the user who created the report
            attributes: ['username'],
          },
          {
            model: Comment,
            as: 'comments',  // Include comments
            include: {
              model: User,  // Include the user who created each comment
              as: 'creator',
              attributes: ['username'],
            }
          }
        ]
      });
    } else {
      reports = await Report.findAll({
        where: { createdBy: userId },  // Filter by userId (creator)
        include: [
          {
            model: User,
            as: 'creator',
            attributes: ['username'],
          },
          {
            model: Comment,
            as: 'comments',
            include: {
              model: User,
              as: 'creator',
              attributes: ['username'],
            }
          }
        ]
      });
    }

    // Convert the reports to a format that can be easily returned as JSON
    const reportsWithDetails = reports.map((report) => ({
      ...report.toJSON(),  // Convert Sequelize instance to plain JSON
      createdBy: report.creator.username,
      image: report.image ? `${baseUrl}${report.image}` : null,
    }));

    res.json(reportsWithDetails);
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).json({ error: "Error fetching reports" });
  }
});


app.get("/report", async (req, res) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let reports;
    if (user.role === "admin") {
      reports = await Report.findAll({
        include: [
          { model: User, as: 'creator', attributes: ['username'] },
          { model: Comment, as: 'comments', include: [{ model: User, as: 'creator', attributes: ['username'] }] }
        ],
      });
    } else {
      reports = await Report.findAll({
        where: { createdBy: userId },
        include: [
          { model: User, as: 'creator', attributes: ['username'] },
          { model: Comment, as: 'comments', include: [{ model: User, as: 'creator', attributes: ['username'] }] }
        ],
      });
    }

    res.json(reports);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching reports" });
  }
});




app.get("/report/:id", async (req, res) => {
  try {
    const reportId = req.params.id;
    const report = await Report.findByPk(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }
    res.json(report);
  } catch (error) {
    console.error("Error fetching report details:", error);
    res.status(500).json({ error: "Error fetching report details" });
  }
});



app.delete("/report/:id", async (req, res) => {
  try {
    const reportId = req.params.id;
    await Report.findByIdAndDelete(reportId);
    notifyAllClients({ type: "delete-report", reportId });
    res.status(200).json({ message: "Report deleted successfully" });
  } catch (error) {
    console.error("Error deleting report:", error);
    res.status(500).json({ error: "Error deleting report" });
  }
});

app.put("/report/:id", async (req, res) => {
  try {
    const reportId = req.params.id;
    const { title, description, state, incidentDate } = req.body;

    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;
    const user = await User.findByPk(userId);

    if (user.role !== "admin") {
      return res
        .status(403)
        .json({ error: "User is not authorized to update report state" });
    }

    const [updated] = await Report.update(
      { title, description, state, incidentDate },
      { where: { id: reportId } }
    );
    if (updated) {
      const updatedReport = await Report.findByPk(reportId);
      res.json(updatedReport);
    } else {
      res.status(404).send('Report not found');
    }
    

    const reportWithDetails = {
      ...updatedReport.toObject(),
      createdBy: (await User.findByPk(updatedReport.createdBy)).username,
      image: updatedReport.image ? `${baseUrl}${updatedReport.image}` : null,
    };

    notifyAllClients({ type: "update-report", reportWithDetails });

    res.status(200).json(reportWithDetails);
  } catch (error) {
    console.error("Error updating report:", error);
    res.status(500).json({ error: "Error updating report" });
  }
});

app.post("/assign-report/:reportId", async (req, res) => {
  try {
    const { userId } = req.body;
    const reportId = req.params.reportId;

    // Asignar el informe al usuario especificado
    await Report.findByIdAndUpdate(reportId, { assignedTo: userId });

    // Enviar notificación al usuario asignado
    await sendNotificationToUser(reportId, userId);

    res.status(200).json({ message: "Informe asignado exitosamente" });
  } catch (error) {
    console.error("Error asignando informe:", error);
    res.status(500).json({ error: "Error asignando informe" });
  }
});

app.put("/mark-report-reviewed/:reportId", async (req, res) => {
  try {
    const reportId = req.params.reportId;

    // Find the report by its primary key and update its state
    const report = await Report.findByPk(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }

    report.state = "REVIEWED";
    await report.save();

    res.status(200).json({ message: "Report marked as reviewed" });
  } catch (error) {
    console.error("Error marking report as reviewed:", error);
    res.status(500).json({ error: "Error marking report as reviewed" });
  }
});


app.post("/report/:id/comment", async (req, res) => {
  try {
    const { text } = req.body;
    const reportId = req.params.id;

    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    // Find the report by its primary key
    const report = await Report.findByPk(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }

    // Create and add the comment
    const comment = await Comment.create({
      text,
      createdBy: userId,
      reportId,
      createdAt: new Date(),
    });

    notifyAllClients({
      type: "new-comment",
      data: { reportId, comment },
    });

    res.status(201).json(comment);
  } catch (error) {
    console.error("Error adding comment:", error);
    res.status(500).json({ error: "Error adding comment" });
  }
});


app.get("/report/:id/comments", async (req, res) => {
  try {
    const reportId = req.params.id;

    // Fetch the report along with its comments and user details
    const report = await Report.findByPk(reportId, {
      include: {
        model: Comment,
        include: { model: User, attributes: ["username"] }, // Include user details
      },
    });

    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }

    res.status(200).json(report.Comments); // Sequelize automatically includes the comments
  } catch (error) {
    console.error("Error fetching comments:", error);
    res.status(500).json({ error: "Error fetching comments" });
  }
});


app.put("/report/:reportId/comment/:commentId", async (req, res) => {
  try {
    const { text } = req.body;
    const { reportId, commentId } = req.params;

    const report = await Report.findByPk(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }

    const comment = report.comments.id(commentId);
    if (!comment) {
      return res.status(404).json({ error: "Comment not found" });
    }

    const token = req.cookies?.token;
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    if (comment.createdBy.toString() !== decodedToken.userId) {
      return res.status(403).json({ error: "User not authorized" });
    }

    comment.text = text;
    await report.save();

    const user = await User.findByPk(decodedToken.userId, "username");
    comment.createdBy = user;

    io.to(reportId).emit("updateComment", comment); // Emitir evento a través de WebSocket

    res.status(200).json(comment);
  } catch (error) {
    console.error("Error updating comment:", error);
    res.status(500).json({ error: "Error updating comment" });
  }
});

app.delete("/report/:reportId/comment/:commentId", async (req, res) => {
  try {
    const { reportId, commentId } = req.params;

    const report = await Report.findByPk(reportId);
    if (!report) {
      return res.status(404).json({ error: "Report not found" });
    }

    const commentIndex = report.comments.findIndex(
      (comment) => comment._id.toString() === commentId
    );
    if (commentIndex === -1) {
      return res.status(404).json({ error: "Comment not found" });
    }

    report.comments.splice(commentIndex, 1);
    await report.save();

    io.to(reportId).emit("deleteComment", commentId); // Emitir evento a través de WebSocket

    res.status(200).json({ message: "Comment deleted successfully" });
  } catch (error) {
    console.error("Error deleting comment:", error);
    res.status(500).json({ error: "Error deleting comment" });
  }
});

app.get("/user/:userId/reports", async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    const reports = await Report.findAll({ createdBy: userId });

    res.status(200).json(reports);
  } catch (error) {
    console.error("Error fetching user reports:", error);
    res.status(500).json({ error: "Error fetching user reports" });
  }
});

async function assignReportAndNotify(reportId, userId) {
  try {
    // Asignar el informe al usuario especificado
    await Report.findByIdAndUpdate(reportId, { assignedTo: userId });

    // Enviar notificación al usuario asignado
    await sendNotificationToUser(reportId, userId);

    return { message: "Informe asignado exitosamente" };
  } catch (error) {
    console.error("Error asignando informe:", error);
    throw new Error("Error asignando informe");
  }
}


/////////////////////////////////////////////////////////////////
// iniciando la parte del Usuario (residente o administrador) //

app.get("/users", async (req, res) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    // Check the user's role
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.role === "admin") {
      const users = await User.findAll();  // Fetch all users for admin
      return res.json(users);
    } else {
      return res.json([user]);  // Non-admins only see their own info
    }
  } catch (error) {
    console.error("Error fetching users:", error);
    return res.status(500).json({ error: "Error fetching users" });
  }
});


app.post("/users", async (req, res) => {
  try {
    const { username, password, email, address, phone, age, residenceType } =
      req.body;
    const newUser = await User.create({
      username,
      password,
      email,
      address,
      phone,
      age,
      residenceType,
      role,
    });
    res.status(201).json(newUser);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creating user" });
  }
});

app.delete("/users/:id", async (req, res) => {
  try {
    const userId = req.params.id;

    // Find and delete the user by primary key
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    await user.destroy();  // Delete the user
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Error deleting user" });
  }
});


app.put("/users/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const {
      username,
      password,
      email,
      address,
      phone,
      age,
      residenceType,
      role,
    } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, password, email, address, phone, age, residenceType, role },
      { new: true }
    );
    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Error updating user" });
  }
});

app.get("/users/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching user" });
  }
});

app.get("/user", async (req, res) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findByPk(decodedToken.userId);
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Error fetching user data" });
  }
});

async function getUserDataFromRequest(req) {
  return new Promise((resolve) => {
    const token = req.cookies?.token;
    if (token) {
      jwt.verify(token, jwtSecret, {}, (err, userData) => {
        if (err) {
          console.error("Error verifying token:", err);
          resolve(null);
        } else {
          resolve(userData);
        }
      });
    } else {
      resolve(null);
    }
  });
}

const storages = multer.memoryStorage();
const uploads = multer({ storages });

app.put("/user", uploads.single("profileImage"), async (req, res) => {
  try {
    const userData = await getUserDataFromRequest(req);
    const userId = userData.userId;

    // Obtener los datos del usuario a actualizar del cuerpo de la solicitud
    const { username, email, address, phone, age, residenceType, role } =
      req.body;

    // Actualizar el usuario autenticado
    const updatedUserData = {
      username,
      email,
      address,
      phone,
      age,
      residenceType,
      role,
    };

    // Si se cargó una imagen de perfil, actualizarla también
    if (req.file) {
      updatedUserData.profileImage = {
        data: req.file.buffer,
        contentType: req.file.mimetype,
      };
    }

    const updatedUser = await User.findByIdAndUpdate(userId, updatedUserData, {
      new: true,
    });

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(updatedUser);
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Error updating user" });
  }
});

app.post("/api/sendPasswordRecoveryEmail", async (req, res) => {
  const { email } = req.body;

  //  las opciones del correo electrónico
  const emailOptions = {
    from: "onboarding@resend.dev",
    to: email,
    subject: "Recuperación de Contraseña",
    html: '<p>Hola, has solicitado restablecer tu contraseña. Sigue este enlace para restablecerla: <a href="http://example.com/reset-password">Restablecer Contraseña</a></p>',
  };

  // Envía el correo electrónico
  try {
    const response = await resend.emails.send(emailOptions);
    console.log("Email sent successfully:", response);
    res.json({ message: "Email enviado exitosamente." });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ message: "Error al enviar el correo electrónico." });
  }
});

const authenticateUser = (req, res, next) => {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: "User not authenticated" });
    }
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decodedToken.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

app.get("/user/me", authenticateUser, async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findByPk(userId).select("-password"); // Excluir el campo de la contraseña
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (error) {
    console.error("Error fetching current user data:", error);
    res.status(500).json({ error: "Error fetching current user data" });
  }
});

// Mensaje reciente //

app.get("/recent-messages", authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.userId; // Ahora puedes acceder a req.user
    const recentMessages = await Message.findAll({ recipient: userId })
      .sort({ createdAt: -1 })
      .limit(5);
    res.json(recentMessages);
  } catch (error) {
    console.error("Error fetching recent messages:", error);
    res.status(500).json({ error: "Error fetching recent messages" });
  }
});



// Use in routes like:
app.get("/user/me", authenticateJWT, (req, res) => {
  res.json(req.user);
});

app.post("/change-password", authenticateJWT, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Incorrect current password" });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, bcryptSalt);

    user.password = hashedNewPassword;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    console.error("Error updating password:", error);
    res.status(500).json({ error: "Error updating password" });
  }
});