const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("./../config");

function tokenBuilder(user) {
  // {id, username, role}
  const payload = {
    userID: user.id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  const result = jwt.sign(payload, JWT_SECRET, options);
  return result;
}

module.exports = tokenBuilder;
