const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

// configs {
const httpPort = 9000;
const saltRounds = 4;
const jwtSecret = 'SECRET! #codeinaction #tmj :D';
const psqlConfig = 'postgres://localhost:5432/codeinaction_login_area';
// } <-- configs

const app = express();

// db utils {
class DbArgs {
    constructor () {
        this._args = [];
    }

    // $N::type
    // .toArray()
    add (value, type) {
        const argIndex = this._args.length + 1;
        const fullType = `$${argIndex}::${type}`;

        this._args.push({ argIndex, value, fullType });
        return fullType;
    }

    toArray () {
        return this._args.map((a) => a.value);
    }
}

class DbBase {
    async execute (stmt, dbArgs) {
        const client = new Client(psqlConfig);
        await client.connect();

        try {
            const dbResponse = await client.query(stmt, dbArgs.toArray());
            client.end();

            return dbResponse;
        } catch (ex) {
            client.end();
            throw new Error(ex);
        }
    }
}

class UserDb extends DbBase {
    async tryFindUserByLogin (login) {
        const args = new DbArgs();

        const stmt = `
            SELECT
                id,
                login,
                password
            FROM
                users
            WHERE
                login = ${args.add(login, 'text')}
        `;

        const dbResult = await this.execute(stmt, args);
        return dbResult.rows[0];
    }

    async createUser (login, password) {
        const args = new DbArgs();
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const stmt = `
            INSERT INTO
                users (login, password)
            VALUES
                (
                    ${args.add(login, 'text')},
                    ${args.add(hashedPassword, 'text')}
                )

            RETURNING
                id, login;
        `;

        const dbResponse = await this.execute(stmt, args);
        return dbResponse.rows[0];
    }
}

class Db {
    constructor () {
        this.users = new UserDb();
    }
}
// } <!-- db utils

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

        const db = new Db();
        const userDb = await db.users.tryFindUserByLogin(user);

        if (userDb) validationError(`User ${user} already registered!`);

        const dbUserResponse = await db.users.createUser(user, password);
        const token = jwt.sign({ userIdb: dbUserResponse.id }, jwtSecret);

        res.status(201).json({ userCreated: true, jwt: token });
    } catch (ex) { errorCatchHandler(ex, req, res); }
}

async function loginUserHandler (req, res) {
    try {
        const { user, password } = getUserAndPasswordByBody(req.body);

        const db = new Db();
        const userDb = await db.users.tryFindUserByLogin(user);

        if (!userDb) validationError(`User ${user} NOT registered!`);

        if (!await bcrypt.compare(password, userDb.password)) {
            validationError(`Invalid login/password`);
        }

        const token = jwt.sign({ userId: userDb.id }, jwtSecret);
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
