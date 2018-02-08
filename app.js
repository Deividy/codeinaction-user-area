const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// configs {
const httpPort = 9000;
const saltRounds = 4;
const jwtSecret = 'SECRET! #codeinaction #tmj :D';
// } <-- configs

const app = express();
const userDb = { };

// util functions {
function validationError (message) {
    const error = new Error(message);
    error.statusCode = 400;

    throw error;
}

function demandString (str, argName) {
    if (!str || Object.prototype.toString.call(str) !== '[object String]') {
        validationError(`Expected string in ${argName} value, but got ${str}`);
    }
}

function getUserAndPasswordByBody (body) {
    const { user, password } = body;

    demandString(user, 'user');
    demandString(password, 'password');

    return { user, password };
}
// } <-- util functions

// handlers {
function errorCatchHandler (error, req, res, next) {
    console.error(error);
    res.status(error.statusCode || 500).json({ error: true, msg: error.message });
}

async function createUserHandler (req, res) {
    try {
        const { user, password } = getUserAndPasswordByBody(req.body);
        if (userDb[user]) validationError(`User ${user} already registered!`);

        userDb[user] = {
            hashedPassword: await bcrypt.hash(password, saltRounds)
        };

        const token = jwt.sign({ user }, jwtSecret);
        res.status(201).json({ userCreated: true, jwt: token });
    } catch (ex) { errorCatchHandler(ex, req, res); }
}

async function loginUserHandler (req, res) {
    try {
        const { user, password } = getUserAndPasswordByBody(req.body);
        if (!userDb[user]) validationError(`User ${user} NOT registered!`);

        const { hashedPassword } = userDb[user];

        if (!await bcrypt.compare(password, hashedPassword)) {
            validationError(`Invalid login/password`);
        }

        const token = jwt.sign({ user }, jwtSecret);
        res.status(200).json({ success: true, jwt: token });
    } catch (ex) { errorCatchHandler(ex, req, res); }
}

function userAreaHandler (req, res) {
    res.status(200).json({ ok: true, user: req.user });
}
// } <-- handlers


// middlewares {
function middlewareJwtValidation (req, res, next) {
    try {
        const token = req.headers.authorization.replace('Bearer ', '');

        jwt.verify(token, jwtSecret);
        const decodedToken = jwt.decode(token);

        req.user = decodedToken.user;

        next();
    } catch (ex) {
        console.error(ex);

        const error = new Error('Unauthorized!');
        error.statusCode = 401;

        throw error;
    }
}
// } <-- middlewares

// routes {
app.post('/create-user', bodyParser.json(), createUserHandler);
app.post('/login-user', bodyParser.json(), loginUserHandler);
app.get('/user-area', middlewareJwtValidation, userAreaHandler);

app.use(function (req, res) {
    res.status(404).json({ notFound: true, code: 404 });
});

app.use(errorCatchHandler);
// } <-- routes

app.listen(httpPort, () => {
    console.log(`Estamos vivos! http://localhost:${httpPort}`);
});
