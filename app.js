const express = require('express');
const mysql2 = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');

const app = express();

var db = mysql2.createConnection({
    host: "Your_host",
    user: "Your_user",
    password: "Your_password",
    database: "Your_database"
});

db.connect(function (err) {
    if (err) throw err;
    console.log("Connected!");
});

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
    secret: 'nodesecret',
    resave: false,
    saveUninitialized: true
}))

app.set('view engine', 'ejs');

function ifLoggedIn(req, res, next) {
    if (req.session.user) {
        return res.redirect('/');
    }
    next();
}

// รับหน้า
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
})
app.get('/login',ifLoggedIn, (req, res) => {
    res.render('login');
})
app.get('/register',ifLoggedIn, (req, res) => {
    res.render('register');
})
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.redirect('/');
        }
        res.clearCookie('connect.sid');
        res.redirect('/');
    });
})

// การสมัครสมาชิก
app.post('/register', (req, res) => {
    const { email, password, password2 } = req.body;
    const checkEmail = 'SELECT * FROM users WHERE email = ?';
    // ดู email ว่าซ้ำไหม
    if (password !== password2) {
        return res.render('register', { password_message: 'Passwords do not match' });
    }

    db.query(checkEmail, [email], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            res.render('register', { Email_already_message: 'Email already exists' });
        } else {
            const hashpassword = bcrypt.hashSync(password, 10);
            const insertUser = 'INSERT INTO users(email, password) VALUES(?, ?)';
            db.query(insertUser, [email, hashpassword], (err, result) => {
                if (err) throw err;
                res.render('register', { register_message: 'Register successfully' });
            });
        }
    });
});

// การ login
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = 'SELECT * FROM users WHERE email = ?';

    db.query(sql, [email], (err, result) => { // แก้ไขการเรียกใช้ db.query
        if (err) throw err;
        if (result.length > 0) {
            const user = result[0];
            if (bcrypt.compareSync(password, user.password)) {
                req.session.user = user;
                res.redirect('/');
            } else {
                res.render('login', { Login_message: 'password is incorrect' });
            }
        }else{
            res.render('login', { Login_message: 'Email is incorrect' });
        }
    });
});

app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});