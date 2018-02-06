const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const httpPort = 9000;
const saltRounds = 4;
const jwtSecret = 'SECRET! #codeinaction #tmj :D';

const app = express();
const userDb = { };

function errorCatchHandler (error, req, res, next) {
    console.error(error);
    res.status(error.statusCode || 500).json({ error: true, msg: error.message });
}

// _.isString()
function demandString (str) {
    if (!str || Object.prototype.toString.call(str) !== '[object String]') {
        const error = new Error(`Expected string value, but got ${str}`);
        error.statusCode = 400;

        throw error;
    }
}

async function createUserHandler (req, res) {
    try {
        // { user: "MEUUSER", password: "MYPASS" }
        const { user, password } = req.body;

        demandString(user);
        demandString(password);

        if (userDb[user]) {
            const error = new Error(`User ${user} already registered!`);
            error.statusCode = 400;

            throw error;
        }

        userDb[user] = {
            hashedPassword: await bcrypt.hash(password, saltRounds)
        };

        const token = jwt.sign({ user }, jwtSecret);
        res.status(201).json({ userCreated: true, jwt: token });
    } catch (ex) { errorCatchHandler(ex, req, res); }
}

async function loginUserHandler (req, res) {
    try {
        const { user, password } = req.body;

        demandString(user);
        demandString(password);

        if (!userDb[user]) {
            const error = new Error(`User ${user} NOT registered!`);
            error.statusCode = 400;

            throw error;
        }

        const { hashedPassword } = userDb[user];

        if (!await bcrypt.compare(password, hashedPassword)) {
            const error = new Error(`Invalid login/password`);
            error.statusCode = 400;

            throw error;
        }

        const token = jwt.sign({ user }, jwtSecret);
        res.status(200).json({ success: true, jwt: token });
    } catch (ex) { errorCatchHandler(ex, req, res); }
}

app.post('/create-user', bodyParser.json(), createUserHandler);
app.post('/login-user', bodyParser.json(), loginUserHandler);

app.use(function (req, res) {
    res.status(404).json({ notFound: true, code: 404 });
});

app.use(errorCatchHandler);

app.listen(httpPort, () => {
    console.log(`Estamos vivos! http://localhost:${httpPort}`);
});
