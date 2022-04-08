const { Strategy } = require('passport-google-oauth2')
const passport = require('passport')
const express = require('express')
const { log } = require('console')
const helmet = require('helmet')
const https = require('https')
require('dotenv').config()
const fs = require('fs')
const app = express()
const cookieSession = require('cookie-session')

const config = {
	CLIENT_ID: process.env.client_id, 
	CLIENT_SECRET: process.env.client_secret,
	COOKIE_KEY_1: process.env.cookie_key_1,
	COOKIE_KEY_2: process.env.cookie_key_2
}
log(process.env.client_id)
const authOption = {
	callbackURL: '/auth/google/callback',
	clientID: config.CLIENT_ID,
	clientSecret: config.CLIENT_SECRET
} 

const verifyCallback = (accessToken, refreshToken, profile, done) => {
	log('google profile', profile)
	done(null, profile)
}

passport.use(new Strategy(authOption, verifyCallback))

//save session to cookies
passport.serializeUser((user, done)=>{
	done(null , user.id)
})


//read session from cookies
passport.deserializeUser((id, done)=>{
	done(null , id) 
})


app.use(helmet())
app.use(cookieSession({
	name:'session',
	maxAge:24 * 60 * 60 * 1000,
	keys:[config.COOKIE_KEY_1, config.COOKIE_KEY_2]
}))
app.use(passport.initialize())
app.use(passport.session())

app.use(express.static('./public'))


const checkLogin = (req, res, next) => {
	log(req.user)
	const userloggedin = req.user && req.isAuthenticated()
	if (!userloggedin) {
		return res.status(401).json({ error: 'you must logged in' })
	}
	next()
}



app.get('/auth/google', passport.authenticate('google', {
	scope: ['email'],
}))

app.get('/auth/google/callback', passport.authenticate('google', {
	failureRedirect: '/failure',
	successRedirect: '/',
	session: true
}), (req, res) => {
	log('google called us')
})


app.get('/failure', (req, res) => {
	res.send('not authorized')
})

app.get('/auth/logout', (req, res) => {
req.logout()
return res.redirect('/')
})




app.get('/secret', checkLogin, (req, res) => {
	res.send('your secret is 98')
})


https.createServer({
	cert: fs.readFileSync('cert.pem'),
	key: fs.readFileSync('key.pem')
}, app).listen(3000, () => {
	console.log('started listenig at port 3000')
})



