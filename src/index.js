require("dotenv").config();

const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const { verifyAccessToken, verifyRefreshToken } = require("./middleware/auth");
const redis_client = require("./redis");
const { generateRefreshToken } = require("./service/auth/token");

const prisma = new PrismaClient();

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Server running");
});

app.post("/signup", async (req, res) => {
  try {
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: hash,
      },
    });
    const userData = { id: user.id, name: user.name, email: user.email };
    const token = jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: 30 });

    const refreshToken = generateRefreshToken(userData);

    await prisma.activity.create({
      data: {
        description: `User with email ${user.email} signed up`,
        email: user.email,
        type: "Sign up",
      },
    });

    res.send({ token, refreshToken, user: userData });
  } catch (error) {
    await prisma.activity.create({
      data: {
        description: `User with email: ${req.body.email} failed to sign up`,
        email: req.body.email,
        type: "Sign up fail",
      },
    });
    res.status(500).send(error);
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        email: req.body.email,
      },
    });
    if (!user) {
      await prisma.activity.create({
        data: {
          description: `User with email: ${req.body.email} failed to login`,
          email: req.body.email,
          type: "Login password fail",
        },
      });
      return res.status(401).send("Invalid username or password");
    }
    const result = bcrypt.compareSync(req.body.password, user.password);
    if (result) {
      const userData = { id: user.id, name: user.name, email: user.email };
      const token = jwt.sign(userData, process.env.JWT_SECRET, {
        expiresIn: 30,
      });

      const refreshToken = generateRefreshToken(userData);

      await prisma.activity.create({
        data: {
          description: `User with email: ${req.body.email} logged in`,
          email: req.body.email,
          type: "Login",
        },
      });

      res.send({ token, refreshToken, user: userData });
    } else {
      await prisma.activity.create({
        data: {
          description: `User with email: ${req.body.email} failed to login`,
          email: req.body.email,
          type: "Login password fail",
        },
      });
      return res.status(401).send({ error: "Invalid username or password" });
    }
  } catch (error) {
    res.status(500).send({ error });
  }
});

app.post("/logout", async (req, res) => {
  try {
    const user = req.body;

    // delete refresh token
    await redis_client.del(user.id, (err) => {
      if (err) throw err;
    });

    // invalidate access token
    await redis_client.set("INVALIDATED_" + user.id, user.token);

    await prisma.activity.create({
      data: {
        description: `User with email: ${req.body.email} logged out`,
        email: req.body.email,
        type: "Logout",
      },
    });
    return res.send({ status: "logged out" });
  } catch (error) {
    console.log("logout error", error);
    res.status(500).send({ error });
  }
});

app.post("/refresh-access-token", verifyRefreshToken, (req, res) => {
  console.log("refreshing access token");
  try {
    const user = req.user;
    const userData = { id: user.id, name: user.name, email: user.email };
    const token = jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: 30 });
    const refreshToken = generateRefreshToken(userData);
    res.send({ token, refreshToken });
  } catch (error) {
    res.status(401).send(error);
  }
});

app.get("/restricted", verifyAccessToken, (req, res) => {
  res.send({ data: "You must be the real user!" });
});

app.get("/current-user", verifyAccessToken, (req, res) => {
  console.log("/current user");
  res.send(req.user);
});

const server = app.listen(4000, "localhost", () => {
  const address = server.address();
  const origin = "http://" + address.address + ":" + address.port;
  console.info(`\nExpress server listening at ${origin}`);
});
