const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors({
  origin: "*"
}));
app.use(express.json());
const path = require("path");

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.send("API rodando 🚀");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Servidor rodando na porta " + PORT);
});
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(() => console.log("Banco conectado 🚀"))
  .catch(err => console.error("Erro ao conectar banco:", err));

  async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100),
      email VARCHAR(100) UNIQUE,
      password VARCHAR(255)
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255),
      completed BOOLEAN DEFAULT false,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  console.log("Tabelas criadas 🚀");
}

createTables();
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Usuário não encontrado" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({ message: "Senha incorreta" });
    }

    const token = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ token });

  } catch (error) {
    res.status(500).json({ message: "Erro no servidor" });
  }
});

function authMiddleware(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "Token não fornecido" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ message: "Token inválido" });
  }
}
app.post("/tasks", authMiddleware, async (req, res) => {
  const { title } = req.body;

  await pool.query(
    "INSERT INTO tasks (title, user_id) VALUES ($1, $2)",
    [title, req.userId]
  );

  res.json({ message: "Tarefa criada" });
});

app.get("/tasks", authMiddleware, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM tasks WHERE user_id = $1 ORDER BY id DESC",
    [req.userId]
  );

  res.json(result.rows);
});
app.put("/tasks/:id", authMiddleware, async (req, res) => {
  const { completed } = req.body;

  await pool.query(
    "UPDATE tasks SET completed = $1 WHERE id = $2 AND user_id = $3",
    [completed, req.params.id, req.userId]
  );

  res.json({ message: "Tarefa atualizada" });
});
app.delete("/tasks/:id", authMiddleware, async (req, res) => {
  await pool.query(
    "DELETE FROM tasks WHERE id = $1 AND user_id = $2",
    [req.params.id, req.userId]
  );

  res.json({ message: "Tarefa deletada" });
});