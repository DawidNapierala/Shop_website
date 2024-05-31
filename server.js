const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const app = express();
const db = new sqlite3.Database(':memory:');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// Initialize session middleware
app.use(session({
  secret: 'secret',
  resave: true,
  saveUninitialized: true
}));
// Create orders and users tables
db.serialize(() => {
    db.run(`CREATE TABLE orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firstName TEXT,
        lastName TEXT,
        email TEXT,
        phone TEXT,
        product TEXT,
        amount INTEGER
    )`);
    
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firstName TEXT,
        lastName TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT
    )`);
});
// Initialize passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Configure passport local strategy for user authentication
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, (email, password, done) => {
  db.get('SELECT * FROM users WHERE email = ? AND password = ?', [email, password], (err, row) => {
    if (err) {
      return done(err);
    }
    if (!row) {
      return done(null, false, { message: 'Incorrect email or password' });
    }
    return done(null, row);
  });
}));

// Endpoint to handle user registration
app.post('/register', (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    const stmt = db.prepare('INSERT INTO users (firstName, lastName, email, password) VALUES (?, ?, ?, ?)');
    stmt.run(firstName, lastName, email, password, function (err) {
        if (err) {
            if (err.code === 'SQLITE_CONSTRAINT') {
                return res.status(400).json({ error: 'Email already in use' });
            }
            return res.status(500).json({ error: err.message });
        }
        res.redirect('/login'); // Redirect to login page after successful registration
    });
    stmt.finalize();
});

// Endpoint to handle user login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/account', // Redirect to account page after successful login
  failureRedirect: '/login', // Redirect back to login page if authentication fails
  failureFlash: true
}));

// Serialize user object to session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user object from session
passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
    if (err) {
      return done(err);
    }
    done(null, row);
  });
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}

// Middleware to check if user is an admin
function isAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') {
    return next();
  }
  res.status(403).send('Access denied');
}

// Add admin user to the database
const adminUser = {
    firstName: 'Admin',
    lastName: 'User',
    email: 'admin@example.com',
    password: 'adminpassword',
    role: 'admin' // Assuming 'role' is a field in your users table to differentiate between admin and regular users
  };
  
  const insertAdminQuery = `INSERT INTO users (firstName, lastName, email, password, role) 
                            VALUES (?, ?, ?, ?, ?)`;
  
  db.run(insertAdminQuery, [adminUser.firstName, adminUser.lastName, adminUser.email, adminUser.password, adminUser.role], function(err) {
    if (err) {
      console.error('Error adding admin user:', err.message);
    } else {
      console.log('Admin user added successfully with ID:', this.lastID);
    }
  });
  
// Define routes

// Account page
app.get('/account', isAuthenticated, (req, res) => {
    // Render the account HTML page
    res.sendFile(path.join(__dirname, 'public', 'account.html'));
});
// Authentication routes
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

// Regular user routes
app.get('/', isAuthenticated, (req, res) => {
  res.send('Regular user dashboard');
});

// Admin panel routes
app.get('/admin/products', isAdmin, (req, res) => {
  res.send('Admin panel - Add products');
});

app.get('/admin/orders', isAdmin, (req, res) => {
  res.send('Admin panel - View orders');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
