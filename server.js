const express = require('express');
const session = require('express-session')
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const url = require('url');
const FileStore = require('session-file-store')(session)

const authCheck = require('./authCheck')

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
    //
    resave: false,
    saveUninitialized: true,
    store: new FileStore()
}))

const port = 9100;

const connection = mysql.createConnection({
    host: 'jabcho.org',
    //
});

connection.connect();

app.get('/', (req, res) => {
    if (!authCheck.isOwner(req, res)) {
        res.redirect('/login')
        return false;
    } else {
        res.send(`Hello, ${req.session.nickname}! <a href="/logout">Logout</a>`);
        return false;
    }
})

app.get('/login', (req, res) => {
    const queryData = url.parse(req.url, true).query;
    const _url = (queryData.url != undefined) ? queryData.url : '/';
    if (!authCheck.isOwner(req, res)) {
        const form = `
            <form action="/auth" method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
                <input type="hidden" name="url" value="${_url}">
                <button type="submit">Login</button>
            </form>
        `;
        res.send(form);
    } else {
        res.redirect(_url);
        return false;
    }
});

app.post('/auth', (req, res) => {
    const { username, password, _url } = req.body;
    connection.query('SELECT * FROM userData WHERE userID = ?', [username], (error, results) => {
        if (error) {   
            return res.status(500).json(error);
        }
        if (results.length > 0) {
            const user = results[0];
            bcrypt.compare(password, user.password, (err, match) => {
                if (err) return res.status(500).json(err);
                if (match) {
                    req.session.is_logined = true;
                    req.session.nickname = username;
                    req.session.save(() => {
                        res.redirect(_url);
                    })
                }
                return res.status(401).send(`<script type="text/javascript">alert("비밀번호가 일치하지 않습니다."); 
                document.location.href="/login";</script>`);
            });
        } else {
            return res.send(`<script type="text/javascript">alert("사용자가 존재하지 않습니다."); 
            document.location.href="/login";</script>`);
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(function (err) {
        res.redirect('/');
    });
});

app.listen(port, () => {
    
});