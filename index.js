const express = require('express')
const session = require('express-session')
const logger = require('morgan')
const fs = require('fs');
const https = require('https')
const config = require('config')
const sqlite3 = require('better-sqlite3')
const cookieParser = require('cookie-parser')
const base64 = require('base64-arraybuffer')

const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const JwtStrategy  = require('passport-jwt').Strategy
const GitHubStrategy = require('passport-github2').Strategy
const OpenIDConnectStrategy = require('openid-client').Strategy
const CustomStrategy = require('passport-custom').Strategy
const Issuer = require('openid-client').Issuer
const RadiusClient = require('node-radius-client');
const {
    dictionaries: {
      rfc2865: {
        file,
        attributes,
      },
    },
  } = require('node-radius-utils');
const jwt = require('jsonwebtoken')
const jwtSecret = Buffer.from(config.get('jwt.secret'), 'base64')

///////////////////
// SCRYPT CONFIG //
///////////////////
const scryptPbkdf = require('scrypt-pbkdf')
const derivedKeyLength = config.get('scrypt.derivedKeyLength')
const scryptParams = config.get('scrypt.FastParams')

//////////////////
// GITHUB OAUTH //
//////////////////
const GITHUB_CLIENT_ID = config.get('github.clientID')
const GITHUB_CLIENT_SECRET = config.get('github.clientSecret')
const GITHUB_CALLBACK_URL = config.get('github.callbackURL')

/////////////////////
/// OIDC STRATEGY ///
/////////////////////
const OIDC_PROVIDER = config.get('oidc.provider')
const OIDC_CLIENT_ID = config.get('oidc.clientID')
const OIDC_CLIENT_SECRET = config.get('oidc.clientSecret')
const OIDC_CALLBACK_URL = config.get('oidc.callbackURL')

const host = config.get('server.host')
const port = config.get('server.port')

/////////////////////
// RADIUS STRATEGY //
/////////////////////
const RADIUS_HOST = config.get('radius.host')
const RADIUS_SECRET = config.get('radius.secret')

//////////////
// DATABASE //
//////////////

function createDatabase() {
    // File database
    fs.writeFileSync('database/credentials.json', '[]')

    // SQLite database
    fs.writeFileSync('database/credentials.db', '')
    const db = new sqlite3('database/credentials.db', { "fileMustExist": false })
    db.prepare('CREATE TABLE credentials (username TEXT PRIMARY KEY, password TEXT NOT NULL, salt TEXT NOT NULL)').run()
}

// Reset the database
// createDatabase()

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

function addUser(username, password, salt) {
    // Read a json file
    credentials = JSON.parse(fs.readFileSync('database/credentials.json', "utf-8"))

    credentials.push({
        "username": username,
        "password": password,
        "salt": salt
    })

    fs.writeFileSync('database/credentials.json', JSON.stringify(credentials))
}

const db = new sqlite3('database/credentials.db', { "fileMustExist": true })

async function existsUserDB(username) {
    exists = false
    user = null

    try {
        user = await db.prepare('SELECT * FROM credentials WHERE username = ?').get(username)
    } catch (error) {
        console.error(error)
    }

    if (user !== undefined) {
        exists = true
    }

    return exists
}

async function getUserDB(username) {
    user = null

    try {
        user = await db.prepare('SELECT * FROM credentials WHERE username = ?').get(username)
    } catch (error) {
        console.error(error)
    }

    if (user === undefined) {
        user = null
    }

    return user
}

async function addUserDB(username, password, salt) {
    try {
        await db.prepare('INSERT INTO credentials (username, password, salt) VALUES (?, ?, ?)').run(username, password, salt)
    } catch (error) {
        console.error(error)
        throw error
    }
}

function generateToken(sub) {
    // This is what ends up in our JWT
    const jwtClaims = {
        sub: sub,
        iss: `${host}:${port}`,
        aud: `${host}:${port}`,
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
    }

    // generate a signed json web token. By default the signing algorithm is HS256 (HMAC-SHA256), i.e. we will 'sign' with a symmetric secret
    return jwt.sign(jwtClaims, jwtSecret)
}

async function main () {
    const app = express()
    app.use(logger('dev'))

    app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
    app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.
    app.use(cookieParser())

    app.use (session({
        secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
        resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
        saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
    }))

    // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
    const oidcIssuer = await Issuer.discover(OIDC_PROVIDER)
    // 2. Setup an OIDC client/relying party.
    const oidcClient = new oidcIssuer.Client({
        client_id: OIDC_CLIENT_ID,
        client_secret: OIDC_CLIENT_SECRET,
        redirect_uris: [OIDC_CALLBACK_URL],
        response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
    })

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
                user = await getUserDB(username)
                if (user === null) {
                    return done(null, false)
                }

                const hash = await scryptPbkdf.scrypt(password, user.salt, derivedKeyLength, scryptParams)
                const hashString = base64.encode(hash)

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
                userExists = await existsUserDB(username)
                if(userExists) {
                    return done(null, false)
                }

                const salt = base64.encode(scryptPbkdf.salt(derivedKeyLength))
                const hash = await scryptPbkdf.scrypt(password, salt, derivedKeyLength, scryptParams)
                const hashString = base64.encode(hash)

                try {
                    await addUserDB(username, hashString, salt)

                    const user = {
                        username: username,
                        description: 'the "only" user that deserves to get to this server'
                    }

                    return done(null, user)
                } catch (error) {
                    return done(null, false)
                }
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
            async function(accessToken, refreshToken, profile, done) {
                if (!profile.username) {
                    return done(null, false)
                }

                userExists = await existsUserDB(profile.username)
                if (!userExists) {
                    try {
                        await addUserDB(profile.username, accessToken, "github-token")
                    } catch (error) {
                        return done(null, false)
                    }
                }

                return done(null, profile)
            }
        )
    )

    passport.use('oidc',
        new OpenIDConnectStrategy(
            {
                client: oidcClient,
                usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
            },
            function (tokenSet, userInfo, done) {
                console.log(tokenSet, userInfo)

                if (tokenSet === undefined || userInfo === undefined) {
                    return done('no tokenSet or userInfo')
                }

                return done(null, userInfo)
            }
        )
    )

    passport.use('radius',
        new CustomStrategy(
            async function (req, done) {
                const username = req.body.username
                const password = req.body.password

                const radiusClient = new RadiusClient({host: RADIUS_HOST})

                try {
                    const response = await radiusClient.accessRequest({
                        secret: RADIUS_SECRET,
                        attributes: [
                          [attributes.USER_NAME, username + "@upc.edu"],
                          [attributes.USER_PASSWORD, password],
                        ],
                      })

                    if (response.code === 'Access-Accept') {
                        const user = {
                            username: username,
                            description: 'the "only" user that deserves to get to this server'
                        }

                        return done(null, user)
                    }
                } catch (error) {
                    console.error(error)
                }

                return done(null, false)
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

    passport.serializeUser(function(user, done) {
        done(null, user)
    })

    passport.deserializeUser(function(user, done) {
        done(null, user)
    })

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
            const token = generateToken(req.user.username)

            res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
            res.redirect('/')

            // And let us log a link to the jwt.io debugger for easy checking/verifying:
            console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
            console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
        }
    )

    app.get('/login-radius',
        (req, res) => {
            res.sendFile('routes/login-radius.html', { root: __dirname })
        }
    )

    app.post('/login-radius',
        passport.authenticate('radius', { session: false, failureRedirect: '/login-radius' }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
        (req, res) => {
            const token = generateToken(req.user.username)

            res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
            res.redirect('/')

            // And let us log a link to the jwt.io debugger for easy checking/verifying:
            console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
            console.log(`Token secret (for verifying the signature): ${jwtSecret.toString('base64')}`)
        }
    )

    app.get("/auth/github/login",
        passport.authenticate("github-oauth", { scope: ["repo:status"] }), /// Note the scope here
        (req, res) => { }
    )

    app.get("/auth/github/callback",
        passport.authenticate("github-oauth", { session: false, failureRedirect: "/login" }),
        (req, res) => {
            const token = generateToken(req.user.username)

            res.cookie('jwt', token, { httpOnly: true, secure: true }) // Write the token to a cookie with name 'jwt' and enable the flags httpOnly and secure.
            res.redirect('/')
        }
    )

    app.get('/auth/oidc/login',
        passport.authenticate('oidc', { scope: 'openid email' })
    )

    app.get("/auth/oidc/callback",
        passport.authenticate("oidc", { session: false, failureRedirect: "/login" }),
        (req, res) => {
            const token = generateToken(req.user.email)

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
            const token = generateToken(req.user.username)

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

    https.createServer({
        key: fs.readFileSync('./certs/server.key'),
        cert: fs.readFileSync('./certs/server.cert')
    }, app).listen(port, () => {
        console.log(`Example app listening at https://${host}:${port}`)
    })
}

main().catch(e => { console.log(e) })
