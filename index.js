const base64Tools = require("./exports/base64ArrayBuffer.js")

const express = require('express')
const logger = require('morgan')
const fs = require('fs');
const https = require('https')
const config = require('config')
const sqlite3 = require('better-sqlite3')

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy  = require('passport-jwt').Strategy
const GitHubStrategy = require('passport-github2').Strategy
const jwt = require('jsonwebtoken')
const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits

const cookieParser = require('cookie-parser')

///////////////////
// SCRYPT CONFIG //
///////////////////
const scryptPbkdf = require('scrypt-pbkdf')
const derivedKeyLength = config.get('scrypt.derivedKeyLength')
const salt = scryptPbkdf.salt(derivedKeyLength)
const scryptParams = config.get('scrypt.FastParams')

//////////////////
// GITHUB OAUTH //
//////////////////
const GITHUB_CLIENT_ID = config.get('github.clientID')
const GITHUB_CLIENT_SECRET = config.get('github.clientSecret')
const GITHUB_CALLBACK_URL = config.get('github.callbackURL')

const app = express()
const host = config.get('server.host')
const port = config.get('server.port')


app.use(logger('dev'))

//////////////
// DATABASE //
//////////////

// delete credentials.db if it exists
fs.writeFileSync('database/credentials.db', '')
const db = new sqlite3('database/credentials.db', {"fileMustExist": false})
db.prepare('CREATE TABLE credentials (username TEXT PRIMARY KEY, password TEXT NOT NULL)').run()

function createDatabase() {
    fs.writeFileSync('database/credentials.json', '[]')
}

// Reset the database
createDatabase()

function existsUser(username) {
    // Read a json file
    credentials = JSON.parse(fs.readFileSync('database/credentials.json', "utf-8"))

    res = false
    credentials.forEach(user => {
        if (user.username === username) {
            res = true
        }
    })

    return res
}

async function existsUserDB(username) {
    exists = false
    user = db.prepare('SELECT * FROM credentials WHERE username = ?').all(username)

    if (user[0] !== undefined) {
        exists = true
    }

    return exists
}

function getUser(username) {
    // Read a json file
    credentials = JSON.parse(fs.readFileSync('database/credentials.json', "utf-8"))

    res = null
    credentials.forEach(user => {
        if (user.username === username) {
            res = user
        }
    })

    return res
}

function getUserDB(username) {
    user = db.prepare('SELECT * FROM credentials WHERE username = ?').get(username)

    if (user[0] === undefined) {
        user = null
    } else {
        user = user[0]
    }

    return user
}

function addUser(username, password) {
    // Read a json file
    credentials = JSON.parse(fs.readFileSync('database/credentials.json', "utf-8"))

    credentials.push({
        "username": username,
        "password": password,
    })

    fs.writeFileSync('database/credentials.json', JSON.stringify(credentials))
}

function addUserDB(username, password) {
    db.prepare('INSERT INTO credentials (username, password) VALUES (?, ?)').run(username, password)
}

////////////////////
// AUTHENTICATION //
////////////////////

/*
Configure the local strategy for using it in Passport.
The local strategy requires a `verify` function which receives the credentials
(`username` and `password`) submitted by the user. The function must verify
that the username and password are correct and then invoke `done` with a user
object, which will be set at `req.user` in route handlers after authentication.
*/
passport.use('login-username-password',
    new LocalStrategy(
        {
            usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
            passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
            session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
        },
        async function (username, password, done) {
            user = getUserDB(username)
            if (user === null) {
                return done(null, false)
            }

            const hash = await scryptPbkdf.scrypt(password, salt, derivedKeyLength, scryptParams)
            const hashString = base64Tools.base64ArrayBuffer(hash)
            if (user.password === hashString) {
                const user = {
                    username: username,
                    description: 'the "only" user that deserves to get to this server'
                }
                return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler
            }

            return done(null, false)  // in passport returning false as the user object means that the authentication process failed.
        }
    )
)

passport.use('signup-username-password',
    new LocalStrategy(
        {
            usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
            passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
            session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
        },
        async function (username, password, done) {
            if(existsUserDB(username) === true) {
                return done(null, false)
            }

            const hash = await scryptPbkdf.scrypt(password, salt, derivedKeyLength, scryptParams)
            const hashString = base64Tools.base64ArrayBuffer(hash)
            addUserDB(username, hashString)
            const user = {
                username: username,
                description: 'the "only" user that deserves to get to this server'
            }
            return done(null, user)
        }
    )
)

passport.use('github-oauth',
    new GitHubStrategy(
        {
            clientID: GITHUB_CLIENT_ID,
            clientSecret: GITHUB_CLIENT_SECRET,
            callbackURL: GITHUB_CALLBACK_URL
        },
        function(accessToken, refreshToken, profile, done) {
            if (!profile.username) {
                return done(null, false)
            }
            if (!existsUserDB(profile.username)) {
                addUserDB(profile.username, accessToken)
            }
            return done(null, profile)
        }
    )
)

passport.use('jwtCookie',
    new JwtStrategy(
        {
            jwtFromRequest: (req) => {
                if (req && req.cookies) return req.cookies.jwt
                return null
            },
            secretOrKey: jwtSecret
        },
        function (jwtPayload, done) {
            if (jwtPayload.sub) {
                const user = {
                    username: jwtPayload.sub,
                    description: 'one of the users that deserve to get to this server',
                    role: jwtPayload.role ?? 'user'
                }
                return done(null, user)
            }
            return done(null, false)
        }
    )
)

function generateToken(user) {
    // This is what ends up in our JWT
    const jwtClaims = {
        sub: user.username,
        iss: `${host}:${port}`,
        aud: `${host}:${port}`,
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    return jwt.sign(jwtClaims, jwtSecret)
}

app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
app.use(cookieParser())

///////////////
// ENDPOINTS //
///////////////

app.get('/',
    passport.authenticate('jwtCookie', { session: false, failureRedirect: '/login' }),
    (req, res) => {
        res.send(`Welcome to your private page, ${req.user.username}!`) // we can get the username from the req.user object provided by the jwtCookie strategy
    }
)

app.get('/login',
    (req, res) => {
        res.sendFile('routes/login.html', { root: __dirname })
    }
)

app.post('/login',
    passport.authenticate('login-username-password', { session: false, failureRedirect: '/login' }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
    (req, res) => {
        const token = generateToken(req.user)

        res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
        res.redirect('/')

        // And let us log a link to the jwt.io debugger for easy checking/verifying:
        console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
        console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
    }
)

app.get("/auth/github",
    passport.authenticate("github-oauth", { scope: ["repo:status"] }), /// Note the scope here
    (req, res) => { }
)

app.get("/auth/github/callback",
    passport.authenticate("github-oauth", { session: false, failureRedirect: "/login" }),
    (req, res) => {
        const token = generateToken(req.user)

        res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
        res.redirect('/')
    }
)

app.get('/signup',
    (req, res) => {
        res.sendFile('routes/signup.html', { root: __dirname })
    }
)

app.post('/signup',
  passport.authenticate('signup-username-password', { session: false, failureRedirect: '/signup' }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    const token = generateToken(req.user)

    res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
    res.redirect('/')

    // And let us log a link to the jwt.io debugger for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
  }
)

app.get('/logout',
    (req, res) => {
        res.clearCookie('jwt')
        res.redirect('/')
    }
)

///////////////////
// ERROR HANDLER //
///////////////////

app.use(function(err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
})

https.createServer({
    key: fs.readFileSync('./certs/server.key'),
    cert: fs.readFileSync('./certs/server.cert')
}, app).listen(port, () => {
    console.log(`Example app listening at https://${host}:${port}`)
})
