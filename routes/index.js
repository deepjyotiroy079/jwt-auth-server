var express = require('express');
var router = express.Router();
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const passport = require('passport');
const jwt = require('jsonwebtoken');

const jwtOptions = {
	jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
	secretOrKey: 'secret'
};

passport.use(new JwtStrategy(jwtOptions, (jwtPayload, done) => {
	if (jwtPayload.sub === 'username') {
	  done(null, { id: 'username' });
	} else {
	  done(null, false);
	}
}));


const authorization = (req, res, next) => {
	const token = req.cookies.access_token;
	if(!token) {
		return res.sendStatus(403);
	} 
	try {
		const data = jwt.verify(token, 'secret')
		req.username = data.username;
    	// req.userRole = data.role;
		return next();
    return next();
	} catch {
		return res.sendStatus(403);
	}
}
/* GET home page. */
router.get('/', function(req, res, next) {
	res.render('index', { title: 'Express' });
});

router.post('/login', (req, res, next) => {
	const { username, password } = req.body;
	if (username === 'username' && password === 'password') {
		const token = jwt.sign({ sub: 'username' }, 'secret');
		// res.json({ token });
		res.cookie("access_token", token, {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			}).status(200)
			.json({ message: "Logged in successfully 😊 👌" });
	} else {
		res.status(401).send('Invalid credentials');
	}
});

router.get('/logout', authorization, (req, res) => {
	return res
	  .clearCookie("access_token")
	  .status(200)  
	  .json({ message: "Successfully logged out 😏 🍀" })
	  .redirect('/');
});

router.get('/protected', authorization, (req, res) => {
	res.send(`
		<div>
			<p>This is a protected link</p>
			<a href="/logout">Logout</a>
		</div>`
	);
});

module.exports = router;
