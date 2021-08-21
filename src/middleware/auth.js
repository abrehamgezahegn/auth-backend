const jwt = require("jsonwebtoken");
const redisClient = require("../redis");

const verifyAccessToken = (req, res, next) => {
  try {
    const user = jwt.verify(req.headers.authorization, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (error) {
    if (error.message === "jwt expired") {
      res.json({ message: "Access token has expired" });
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
