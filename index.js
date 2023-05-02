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

app.get('/', (req,res) => {
    var html = `
    <form action='/signup' method='get'>
    <button>Sign Up</button>
    </form>
    <form action='/login' method='get'>
    <button>Login</button>
    </form>
    `;
    if (req.session.authenticated) {
        var user = req.session.user;
        var html = `
        <h3>Hello, ${user}</h3>
        <form action='/members' method='get'>
        <button>Members</button>
        </form>
        <form action='/logout' method='get'>
        <button>Log Out</button>
        </form>
        `;
    }
    res.send(html);
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
    var id = Math.floor(Math.random() * 3) + 1;
    var username = req.session.user
    if (!req.session.authenticated) {
        console.log("user not logged in");
        res.redirect("/");
    }
    switch (id) {
        case 1:
          res.send(`    
          <h1>Hello, ${username}</h1>
          <img src='/blade.gif' style='width:500px';/>  
          <form action='/logout' method='GET'>
            <button>Sign Out</button>
          </form>`);
          break;
        case 2:
          res.send(`    
          <h1>Hello, ${req.session.user}</h1>
          <img src='/March7th.gif' style='width:500px';/>  
          <form action='/logout' method='GET'>
            <button>Sign Out</button>
          </form>`);
          break;
        case 3:
          res.send(`    
          <h1>Hello, ${username}</h1>
          <img src='/MC.gif' style='width:500px';/>  
          <form action='/logout' method='GET'>
            <button>Sign Out</button>
          </form>`);
          break;
        }
});

app.get('/signup', (req,res) => {
    var html = `
    <h3>Create Account</h3>
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='name'>
    <br>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req,res) => {
    var html = `
    <h3>Log In</h3>
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <br>
    <input name='password' type='password' placeholder='password'>
    <br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
       var html = `
        <form action='/signup' method='GET'>
        <div>${validationResult.error.message}</div>
        <br>
        <button>Try Again</button>
        </form>
        `;
        res.send(html);
        return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("created user");
    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    req.session.authenticated = true;
    req.session.user = result[0].username;
	req.session.email = email;
	req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().max(40).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       var html = `
       <form action='/login' method='GET'>
       <div>Invalid username/passsword combination</div>
       <br>
       <button>Try Again</button>
       </form>
       `;
       res.send(html);
       return;
	}

    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();
    console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		var html = `
       <form action='/login' method='GET'>
       <div>Invalid username/passsword combination</div>
       <br>
       <button>Try Again</button>
       </form>
       `;
       res.send(html);
       return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
        req.session.user = result[0].username;
		req.session.email = email;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/');
		return;
	}
	else {
		console.log("incorrect password");
		var html = `
       <form action='/login' method='GET'>
       <div>Invalid username/passsword combination</div>
       <br>
       <button>Try Again</button>
       </form>
       `;
       res.send(html);
       return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.redirect('/members');
    res.send(html);
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
    
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port "+port);
}); 