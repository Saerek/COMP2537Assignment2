require('dotenv').config();

require("./utils.js");

const express = require('express');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const session = require('express-session');
const MongoStore = require('connect-mongo');

const port = process.env.PORT || 8080;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongodb_database = process.env.MONGODB_DATABASE;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

app.set('view engine', 'ejs');

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
        secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => {
    res.render("homepage", {
        user: req.session.user,
        authenticated: req.session.authenticated
    });
});

app.get('/nosql-injection', async (req,res) => {
    var username = req.query.user;
    
	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        console.log("user not logged in");
        res.redirect("/");
    }
    res.render("members", {
        username: req.session.user
    });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    
    const result = await userCollection.find().project({username: 1, _id: 1}).toArray();

    res.render("admin", {users: result});
});

app.get('/signup', (req,res) => {
    res.render("signup")
});

app.get('/login', (req,res) => {
    res.render("login")
});


app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    
    const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});

	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       res.render("signupError", {
        validation: validationResult.error.message
       });
       return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "user"});
	console.log("created user");
    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    req.session.authenticated = true;
    req.session.user = result[0].username;
	req.session.email = email;
	req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(40).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       res.render("loginError");
       return;
	}

    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, user_type: 1, _id: 1}).toArray();
    console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.render("loginError");
        return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.user = result[0].username;
		req.session.email = email;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/');
		return;
	}
	else {
		console.log("incorrect password");
		res.render("loginError");
        return;
	}
});

app.use('/loggedin', sessionValidation);

app.get('/loggedin/info', (req,res) => {
    res.render("loggedin-info");
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect('/members');
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
    
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
    res.status(404);
    res.render("404")
})

app.listen(port, () => {
    console.log("Node application listening on port "+port);
}); 