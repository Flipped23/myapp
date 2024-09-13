'use strict'

/**
 * Module dependencies.
 */

var express = require('express');
var bcrypt = require('bcrypt');
var path = require('path');
var session = require('express-session');
var multer = require('multer');
const { hash } = require('crypto');
const fs = require('fs');
const sentMail = require('./utils/mailer');

var app = module.exports = express();

// config

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const port = process.env.PORT || 3000;
app.set('port', port);

// middleware

app.use(express.urlencoded({ extended: false }))
app.use(session({
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
    secret: 'shhhh, very secret'
}));

// Session-persisted message middleware

app.use(function (req, res, next) {
    var err = req.session.error;
    var msg = req.session.success;
    delete req.session.error;
    delete req.session.success;
    res.locals.message = '';
    if (err) res.locals.message = '<p class="msg error">' + err + '</p>';
    if (msg) res.locals.message = '<p class="msg success">' + msg + '</p>';
    next();
});

// dummy database

let users = [];
const usersFilePath = path.join(__dirname, 'data/users.json');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'public/uploads'));
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });


fs.readFile(usersFilePath, 'utf8', async (err, data) => {
    if (err) {
        if (err.code === 'ENOENT') {
            console.log('users.json file not found, creating a new one.');
            fs.writeFileSync(usersFilePath, JSON.stringify({ users: [] }), 'utf8');
        } else {
            console.error('Error reading user data:', err);
        }
    } else {
        users = JSON.parse(data).users;

        // 哈希化密码
        for (let user of users) {
            if (!user.password.startsWith('$2b$')) { // 检查密码是否已经哈希化
                user.password = await bcrypt.hash(user.password, 10);
            }
        }

        // 写回哈希化后的用户数据
        fs.writeFileSync(usersFilePath, JSON.stringify({ users }), 'utf8');
        console.log('Passwords hashed and users.json updated.');
    }
});

// when you create a user, generate a salt
// and hash the password ('foobar' is the pass here)

// bcrypt.hash('foobar', 10, function (err, hash) {
//     if (err) throw err;
//     // store the hash in the "db"
//     users.tj.hash = hash;
//   });

// Authenticate using our plain-object database of doom!

function authenticate(username, password, callback) {
    const user = users.find(u => u.username === username);
    if (!user) return callback(null, null);
    bcrypt.compare(password, user.password, (err, res) => {
        if (err) return callback(err);
        if (res) return callback(null, user);
        callback(null, null);
    });
}

function restrict(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        req.session.error = 'Access denied!';
        res.redirect('/login');
    }
}

app.get('/', function (req, res) {
    res.redirect('/login');
});

app.get('/restricted', restrict, function (req, res) {
    res.render('restricted', { user: req.session.user });
});

app.get('/logout', function (req, res) {
    // destroy the user's session to log them out
    // will be re-created next request
    req.session.destroy(function () {
        res.redirect('/');
    });
});

app.get('/login', function (req, res) {
    res.render('login');
});

app.post('/login', function (req, res, next) {
    authenticate(req.body.username, req.body.password, function (err, user) {
        if (err) return next(err)
        if (user) {
            // Regenerate session when signing in
            // to prevent fixation
            req.session.regenerate(function () {
                // Store the user's primary key
                // in the session store to be retrieved,
                // or in this case the entire user object
                req.session.user = user;
                req.session.success = 'Authenticated as ' + user.name
                    + ' click to <a href="/logout">logout</a>. '
                    + ' You may now access <a href="/restricted">/restricted</a>.';

                // 发送认证邮件
                const subject = 'Login Notification';
                const text = 'You have logged in to our site.';
                const html = '<p>You have logged in to our site.</p>';
                sentMail(user.email, subject, text, html);
                res.redirect('/restricted');
            });
        } else {
            req.session.error = 'Authentication failed, please check your '
                + ' username and password.'
                + ' (use "tj" and "foobar")';
            res.redirect('/login');
        }
    });
});

app.post('/upload', restrict, upload.array('uploads', 10), function (req, res) {
    console.log(req.files);
    res.redirect('back');
});

app.get('/contact', restrict, function (req, res) {
    res.render('contact');
});

app.get('/upload', restrict, function (req, res) {
    res.render('upload');
});

app.get('/resources', restrict, (req, res) => {
    const pdfs = fs.readdirSync(path.join(__dirname, 'public/pdfs'));
    res.render('resources', { pdfs });
});

app.get('/resources/:filename', restrict, (req, res) => {
    const filename = req.params.filename;
    const pdfUrl = `/pdfs/${filename}`;
    res.render('pdfviewer', { pdfUrl });
});

app.get('/download/:filename', restrict, (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(__dirname, 'public/pdfs', filename);
    res.download(filePath, filename, (err) => {
        if (err) {
            console.error('Error downloading file:', err);
            res.status(500).send('Error downloading file');
        }
    });
});

/* istanbul ignore next */
if (!module.parent) {
    app.listen(3000);
    console.log('Express started on port 3000');
}