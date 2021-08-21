require("dotenv").config();

const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const { verifyAccessToken, verifyRefreshToken } = require("./middleware/auth");
const redis_client = require("./redis");

const prisma = new PrismaClient();

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Server running");
});

app.post("/signup", async (req, res) => {
  try {
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(req.body.password, salt);
    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: hash,
      },
    });
    const userData = { id: user.id, name: user.name, email: user.email };
    const token = jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: 30 });
    const refreshToken = jwt.sign(userData, process.env.JWT_SECRET, {
      expiresIn: 60 * 60 * 24 * 7,
    }); // 7days

    redis_client.get(user.id.toString(), (err, data) => {
      if (err) throw err;

      redis_client.set(
        user.id.toString(),
        JSON.stringify({ token: refreshToken })
      );
    });

    res.send({ token, refreshToken, user: userData });
  } catch (error) {
    res.status(500).send(error);
  }
});

app.get("/login", (req, res) => {
  res.send("Login");
});

app.post("/refresh-access-token", verifyRefreshToken, (req, res) => {
  const user = req.user;
  const userData = { id: user.id, name: user.name, email: user.email };
  const token = jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: 30 });
  const refreshToken = jwt.sign(userData, process.env.JWT_SECRET, {
    expiresIn: 60 * 60 * 24 * 7,
  }); // 7days

  redis_client.get(user.id.toString(), (err, data) => {
    if (err) throw err;

    redis_client.set(
      user.id.toString(),
      JSON.stringify({ token: refreshToken })
    );
  });

  res.send({ token, refreshToken });
});

app.get("/restricted", verifyAccessToken, (req, res) => {
  res.send({ data: "You must be the real user!" });
});

app.get("/current-user", verifyAccessToken, (req, res) => {
  res.send(req.user);
});

const server = app.listen(4000, "localhost", () => {
  const address = server.address();
  const origin = "http://" + address.address + ":" + address.port;
  console.info(`\nExpress server listening at ${origin}`);
});