const redis = require("redis");

// connect to redis
const redis_client = redis.createClient(
  process.env.REDIS_PORT,
  process.env.REDIS_HOST
);

redis_client.on("connect", function () {
  console.log("redis client connected");
});

redis_client.on("error", function (error) {
  console.error(error);
});

module.exports = redis_client;
