const jwt = require("jsonwebtoken");
const redisClient = require("../redis");

const verifyAccessToken = (req, res, next) => {
  try {
    const accessToken = req.headers.authorization;
    const user = jwt.verify(accessToken, process.env.JWT_SECRET);

    redisClient.get("INVALIDATED_" + accessToken, (err, data) => {
      if (err) throw err;
      // token is invalidated
      if (data === accessToken)
        res.status(401).send({ message: "Invalid auth" });
    });

    req.user = { ...user, token: req.headers.authorization };
    next();
  } catch (error) {
    console.log("error", error);
    if (error.message === "jwt expired") {
      res.json({ message: "Access token has expired" });
    } else {
      res.status(401).json({ message: "Un-auth request" });
    }
  }
};

const verifyRefreshToken = (req, res, next) => {
  try {
    const refreshToken = req.body.token;
    if (!refreshToken) return res.status(401).send("Invalid request");
    const user = jwt.verify(refreshToken, process.env.JWT_SECRET);
    redisClient.get(user.id.toString(), (err, data) => {
      if (err) throw err;
      if (data === null) return res.status(401).send("RT not found");
      if (JSON.parse(data).token !== refreshToken.toString()) {
        return res.status(401).send("Invalid request. RT not matching");
      }
      req.user = user;
      next();
    });
  } catch (error) {
    res.status(401).json(error);
  }
};

module.exports = {
  verifyAccessToken,
  verifyRefreshToken,
};
