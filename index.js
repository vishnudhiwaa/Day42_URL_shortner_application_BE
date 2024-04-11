
const express = require("express");
const app = express();
const cors = require("cors");
const mongodb = require("mongodb");
const mongoClient = mongodb.MongoClient;
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const randomstring = require("randomstring");
require("dotenv").config();
const url = require("./config");
const URL = process.env.LINK;
const DB = process.env.DB;
const jwt_secret = process.env.JWT_SECRET;
const FROM = process.env.FROM;
const PASSWORD = process.env.PASSWORD;
//MiddleWare
app.use(cors());
app.use(express.json());


let authenticate = function (request, response, next) {
  if (request.headers.authorization) {
    let verify = jwt.verify(request.headers.authorization, jwt_secret);
    console.log(verify);
    if (verify) {
      request.userid = verify.id;

      next();
    } else {
      response.status(401).json({
        message: "Unauthorized",
      });
    }
  } else {
    response.status(401).json({
      message: "Unauthorized",
    });
  }
};

app.get("/", function (request, response) {
  response.send({message:"Submitted and coded by Jagadeesh Kumar . S, you may send mail to my email address which is jagadeesh_2k17@proton.me, you may contribute some money to my Indian Unified Payment Interface (UPI) which is jagadeesh-kumar@ybl ."});
});

//Login User
app.post("/", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    const user = await db
      .collection("users")
      .findOne({ username: request.body.username });

    if (user) {
      const match = await bcrypt.compare(request.body.password, user.password);
      if (match) {
        const token = jwt.sign(
          { id: user._id, username: user.username, active: user.active },
          jwt_secret
        );

        response.json({
          message: "Successfully Logged In!!",
          active: user.active,
          token,
        });
      } else {
        response.json({
          message: "Password is incorrect!!",
        });
      }
    } else {
      response.json({
        message: "User not found",
      });
    }
    await connection.close();
  } catch (error) {
    console.log(error);
  }
});

//Register
app.post("/register", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(request.body.password, salt);
    request.body.password = hash;
    let checkUser = await db
      .collection("users")
      .findOne({ username: request.body.username });
    if (checkUser) {
      response.json({
        message: "Username already exists. Please choose other username",
      });
    } else if(!checkUser){
      let emailIDCheck = await db
        .collection("users")
        .findOne({ email: request.body.email });
      if (!emailIDCheck) {   
        await db.collection("users").insertOne(request.body);
        let link = "https://url-shortener-application-frontend.vercel.app/activate-account";
        let mailid = request.body.email;    
        await connection.close();
        var transporter = nodemailer.createTransport({
          service: "gmail",
          auth: {
            user: FROM,
            pass: PASSWORD,
          },
        });
       
        var mailOptions = {
          from: FROM,
          to: mailid,
          subject: "URL Shortener",
          text: `Please activate the account by clicking this link`,
          html: `<h2>  Click the link to activate account ${link}</h2>`,
        };

        transporter.sendMail(mailOptions, function (error, info) {
          if (error) {
            console.log(error);
            response.json({
              message: "Email not send",
            });
          } else {
            console.log("Email sent: " + info.response);
            response.json({
              message: "Email Send",
            });
          }
        });
        response.json({
          message:
            "User Registered! Please check the mail and activate the account",
        });
      } else {
        response.json({
          message:
            "Already a registered User.Please use different mailID or Use Forgot password to reset password",
        });
      }
    }
  } catch (error) {
    console.log(error);
  }
});

//Activate Account
app.post("/activate-account", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    const activeStatus = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (activeStatus) {
      if (activeStatus.active === false) {
        await db
          .collection("users")
          .updateOne({ email: request.body.email }, { $set: { active: true } });
        response.json({
          message: `${activeStatus.username} Your account is activated!`,
        });
      } else {
        response.json({
          message: `${activeStatus.username} Your account is already activated`,
        });
      }
    } else {
      response.json({
        message: `Your email ID is not found`,
      });
    }
  } catch (error) {
    console.log(error);
  }
});

//Reset Password
app.post("/resetpassword", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    const user = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (user) {
      let mailid = request.body.email;
      let SecurityCode = randomstring.generate(7);
      let link = "https://url-shortener-application-frontend.vercel.app/reset-password-page";
      await db
        .collection("users")
        .updateOne({ email: mailid }, { $set: { SecurityCode: SecurityCode } });
      await connection.close();

      var transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: FROM,
          pass: PASSWORD,
        },
      });

      var mailOptions = {
        from: FROM,
        to: mailid,
        subject: "Password Reset ",
        text: `Your Security code is ${SecurityCode}. Click the link to reset password ${link}`,
        html: `<h2> Your Security code is ${SecurityCode}. Click the link to reset password ${link}</h2>`,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
          response.json({
            message: "Email not send",
          });
        } else {
          console.log("Email sent: " + info.response);
          response.json({
            message: "Email Send",
          });
        }
      });
      response.json({
        message: "Email Send",
      });
    } else {
      response.json({
        message: "Email Id not match / User not found",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/reset-password-page", async function (request, response) {
  let String = request.body.SecurityCode;
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(request.body.password, salt);
    request.body.password = hash;
    const user = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (user) {
      if (user.SecurityCode === request.body.SecurityCode) {
        await db
          .collection("users")
          .updateOne(
            { SecurityCode: String },
            { $set: { password: request.body.password } }
          );
        response.json({
          message: "Password reset done",
        });
      } else {
        response.json({
          message: "Security code is incorrect",
        });
      }
    } else {
      response.json({
        message: "Email Id not match / User not found",
      });
    }
    await db
      .collection("users")
      .updateOne({ SecurityCode: String }, { $unset: { SecurityCode: "" } });
  } catch (error) {
    console.log(error);
  }
});

//Enter Short URL
app.post("/enterurl", authenticate, async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    if (request.body.longURL == "") {
      response.json({
        message: "Please enter URL",
      });
    } else {
      request.body.userid = mongodb.ObjectId(request.userid);
      let random = randomstring.generate(5);
      request.body.shortURL = `${url}/${random}`;
      const user = await db.collection("urls").insertOne(request.body);
      await connection.close();
      response.json({
        message: "URL added",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

//Get URL's
app.get("/enterurl", authenticate, async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    const data = await db
      .collection("urls")
      .find({ userid: mongodb.ObjectId(request.userid) })
      .toArray();
    if (data) {
      response.json(data);
    } else {
      console.log("User not found");
      response.json({
        message: "User not found",
      });
    }
    await connection.close();
  } catch (error) {
    console.log(error);
  }
});

//Dashboard
app.get("/dashboard", authenticate, async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    let data = db
      .collection("urls")
      .find({ userid: mongodb.ObjectId(request.userid) })
      .toArray();
    if (data) {
      response.json(data);
    } else {
      response.json("error");
    }
  } catch (error) {
    console.log(error);
  }
});

app.get("/:shortURL", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    let data = await db
      .collection("urls")
      .findOne({ shortURL: `${url}/${request.params.shortURL}` });
    if (data) {
      let res = await db
        .collection("urls")
        .updateOne(
          { shortURL: `${url}/${request.params.shortURL}` },
          { $inc: { count: 1 } }
        );
      if (res) {
        response.redirect(data.longURL);
      } else {
        response.json({
          message: "something went wrong",
        });
      }
    } else {
      response.json({
        message: "something went wrong",
      });
    }
    await connection.close();
  } catch (error) {
    console.log(error);
  }
});

app.listen(process.env.PORT || 3007);
