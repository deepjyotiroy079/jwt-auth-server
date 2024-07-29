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

/* GET home page. */
router.get('/', function(req, res, next) {
	res.render('index', { title: 'Express' });
});

router.post('/login', (req, res, next) => {
	const { username, password } = req.body;
	if (username === 'username' && password === 'password') {
		const token = jwt.sign({ sub: 'username' }, 'secret');
		res.json({ token });
	} else {
		res.status(401).send('Invalid credentials');
	}
});

router.get('/protected', passport.authenticate('jwt', { session: false }), (req, res) => {
	res.json({ message: 'You are authorized to access this resource' });
});
module.exports = router;
