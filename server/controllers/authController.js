const bcrypt = require("bcryptjs");

module.exports = {
  register: async (req, res) => {
    const { username, password, isAdmin } = req.body;
    const db = req.app.get("db");
    const result = db.get_user([username]);
    const exsitingUser = result[0];
    if (exsitingUser) {
      return res.status(409).send("Username taken");
    }
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const registeredUser = await db.register_user([isAdmin, username, hash]);
    let user = registeredUser[0];
    // user = registeredUser;
    req.session.user = {
      isAdmin: user.is_admin,
      id: user.id,
      username: user.username
    };
    res.status(201).send(req.session.user);
  },
  login: async (req, res) => {
    const { username, password } = req.body;
    const foundUser = await req.app.get("db").get_user([username]);
    const user = foundUser[0];
    if (!user) {
      return res
        .status(401)
        .send(
          "User not found. Please register as a new user before logging in."
        );
    }
    const isAuthenitcated = bcrypt.compareSync(password, user.hash);
    if (!isAuthenitcated) {
      return res.status(403).send("Incorrect password");
    }
    req.session.user = {
      isAdmin: user.is_admin,
      id: user.id,
      username: user.username
    };
    return res.send(req.session.user);
  },
  logout: async (req, res) => {
    req.session.destroy();
    return res.sendStatus(200);
  }
};
