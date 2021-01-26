const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const ACCESS_TOKEN_SECRET = "VV%m=U9Png3xsdfxgcF#4@n6aR";
const REFRESH_TOKEN_SECRET = "PmcMe3?h4wqserNQ#@nMn!$9";

const app = express();

app.use(cors());
app.use(express.json());

app.use((error, req, res, next) => {
  if (
    error instanceof SyntaxError &&
    (req.method == "POST" || req.method == "PATCH")
  ) {
    res.status(400).json({
      error: error.name,
      message: error.message,
      type: error.type,
    });
  } else {
    next();
  }
});

const ExisitingUsers = [
  {
    username: "sid",
    password: "sid",
    email: "sid@sid.com",
  },
  {
    username: "manish",
    password: "manish",
    email: "manish@manish.com",
  },
];

const checkForUsernamePass = (req, res, next) => {
  if (req.body.username == null)
    return res.status(400).json({ error: "no username" });
  if (req.body.password == null)
    return res.status(400).json({ error: "no password" });
  next();
};

app.post("/auth/signup", checkForUsernamePass, async (req, res) => {
  if (req.body.email == null)
    return res.status(400).json({ error: "no email" });
  const user = ExisitingUsers.filter(
    (user) => user.username == req.body.username
  )[0];
  if (user) return res.status(400).json({ error: "username is taken" });

  const newUser = {
    username: req.body.username,
    password: req.body.password,
    email: req.body.email,
  };
  ExisitingUsers.push(newUser);

  res.status(201).json(newUser);
});

app.post("/auth/login", checkForUsernamePass, async (req, res) => {
  const user = ExisitingUsers.filter(
    (user) => user.username == req.body.username
  )[0];

  if (!user) return res.status(400).json({ error: "no user found" });

  if (user.password != req.body.password)
    return res.status(400).json({ error: "invalid password" });

  const jwt_payload = {
    user: user.username,
    email: user.email,
  };

  try {
    const accessToken = jwt.sign(jwt_payload, ACCESS_TOKEN_SECRET, {
      expiresIn: "1d",
    });
    const refreshToken = jwt.sign(jwt_payload, REFRESH_TOKEN_SECRET, {
      expiresIn: "30d",
    });

    return res.json({
      username: user.username,
      email: user.email,
      accessToken: accessToken,
      refreshToken: refreshToken,
    });
  } catch (error) {
    console.error(error);
    res
      .json({
        error: error,
        message: "Internal Server Error, Please try again Later",
      })
      .status(500);
  }
});

app.post("/auth/token", async (req, res) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken)
    return res.status(403).json({
      error: "no refrsh token",
    });

  jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: "invalid refresh token" });

    const newAccessToken = jwt.sign(
      { username: user.username, email: user.email },
      ACCESS_TOKEN_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.json({ username: user.username, accessToken: newAccessToken });
  });
});

const checkJWT = async (req, res, next) => {
  // Get auth header value

  try {
    let bearerToken;
    if (req.query.authorization) bearerToken = req.query.authorization;
    else if (req.headers["authorization"])
      bearerToken = req.headers["authorization"].split(" ")[1] || "";
    if (!bearerToken)
      return res.status(403).json({
        error: "forbidden - no authorization token",
      });

    jwt.verify(bearerToken, ACCESS_TOKEN_SECRET, (err, data) => {
      if (err)
        return res
          .json({
            error: "invalid authrization token",
          })
          .status(401);

      next();
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      error: "somthing went wrong",
    });
  }
};

app.get("/protected", checkJWT, async (req, res) => {
  res.json({ info: "this is protected route" });
});

app.listen(5500, () => console.log("server stared on 5500"));
