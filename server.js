const express = require("express");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();
app.use(express.json());
app.use(passport.initialize());

const SECRET = "segredo-super";

let users = [];

users.push({ email: "admin@gmail.com", password: "123", role: "admin" });

const API_KEYS = ["minha-chave-123"];


passport.use(new GoogleStrategy({
  clientID: "TESTE",
  clientSecret: "TESTE",
  callbackURL: "/auth/google/callback"
},
(accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));


app.post("/register", (req, res) => {
  const { email, password } = req.body;

  const userExists = users.find(u => u.email === email);
  if (userExists) {
    return res.status(400).send("Usuário já existe");
  }

  users.push({ email, password, role: "user" });

  res.send("Usuário criado com sucesso!");
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const user = users.find(
    u => u.email === email && u.password === password
  );

  if (!user) {
    return res.status(401).send("Email ou senha inválidos");
  }

  const token = jwt.sign(
    { email: user.email, role: user.role },
    SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send("Sem token");
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).send("Token inválido");
  }
}

function isAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).send("Acesso só para admin");
  }
  next();
}

function apiKeyAuth(req, res, next) {
  const key = req.headers["x-api-key"];

  if (!API_KEYS.includes(key)) {
    return res.status(403).send("API Key inválida");
  }

  next();
}

app.get("/", (req, res) => {
  res.send("API funcionando!");
});

app.get("/perfil", auth, (req, res) => {
  res.json({
    message: "Bem-vinda! 🔐",
    user: req.user
  });
});

app.get("/admin", auth, isAdmin, (req, res) => {
  res.send("Área do admin 👑");
});

app.get("/dados-api", apiKeyAuth, (req, res) => {
  res.send("Dados protegidos por API Key 🔑");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    res.send("Login com Google feito com sucesso 🎉");
  }
);

app.listen(3000, () => {
  console.log("Servidor rodando em http://localhost:3000");
});