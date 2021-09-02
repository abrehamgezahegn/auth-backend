const redis_client = require("../../redis");
const jwt = require("jsonwebtoken");

const generateRefreshToken = (userData) => {
  const refreshToken = jwt.sign(userData, process.env.JWT_SECRET, {
    expiresIn: 60 * 60 * 24 * 7,
  }); // 7days

  redis_client.get(userData.id.toString(), (err, data) => {
    if (err) throw err;

    redis_client.set(
      userData.id.toString(),
      JSON.stringify({ token: refreshToken })
    );
  });

  return refreshToken;
};

module.exports = {
  generateRefreshToken,
};
