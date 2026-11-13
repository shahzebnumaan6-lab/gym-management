require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Open login page first
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Make public folder files accessible
app.use(express.static('public', { index: false }));
// FitZone login session
app.use(session({
    
    name: 'fitzone.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
        maxAge: 1000 * 60 * 60 * 8
    }
}));

// Connect to MySQL
// Connect to MySQL
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('MySQL connection failed:', err.message);
        return;
    }

    console.log('Connected to MySQL database!');
});
// ===============================
// FITZONE AUTHENTICATION
// ===============================

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            error: 'Email and password are required.'
        });
    }

    const sql = `
        SELECT user_id, username, email, password_hash,
               role, member_id, trainer_id
        FROM Users
        WHERE email = ?
    `;

    db.query(sql, [email.trim()], async (err, results) => {
        if (err) {
            console.error('Login error:', err);
            return res.status(500).json({
                error: 'Login failed. Please try again.'
            });
        }

        if (results.length === 0) {
            return res.status(401).json({
                error: 'Invalid email or password.'
            });
        }

        const user = results[0];

        try {
            const passwordMatches = await bcrypt.compare(
                password,
                user.password_hash
            );

            if (!passwordMatches) {
                return res.status(401).json({
                    error: 'Invalid email or password.'
                });
            }

            req.session.regenerate((sessionError) => {
                if (sessionError) {
                    return res.status(500).json({
                        error: 'Could not create login session.'
                    });
                }

                req.session.user = {
                    user_id: user.user_id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    member_id: user.member_id,
                    trainer_id: user.trainer_id
                };

                req.session.save((saveError) => {
                    if (saveError) {
                        return res.status(500).json({
                            error: 'Could not save login session.'
                        });
                    }

                    res.json({
                        message: 'Login successful!',
                        user: {
                            username: user.username,
                            role: user.role
                        }
                    });
                });
            });
        } catch (error) {
            console.error('Password verification error:', error);
            res.status(500).json({
                error: 'Something went wrong during login.'
            });
        }
    });
});


// Check whether a user is logged in
app.get('/api/auth/me', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            error: 'You are not logged in.'
        });
    }

    res.json({
        user: req.session.user
    });
});


// Logout
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                error: 'Could not log out.'
            });
        }

        res.clearCookie('fitzone.sid');

        res.json({
            message: 'Logged out successfully!'
        });
    });
});

// Register a new Gym Member
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({
                error: 'Please fill in all fields.'
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: 'Password must be at least 6 characters.'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = `
            INSERT INTO Users (username, email, password_hash, role)
            VALUES (?, ?, ?, 'member')
        `;

        db.query(sql, [username, email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({
                        error: 'This email is already registered.'
                    });
                }

                console.error(err);
                return res.status(500).json({
                    error: 'Registration failed.'
                });
            }

            res.status(201).json({
                success: true,
                message: 'Account created successfully! Please sign in.'
            });
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: 'Something went wrong during registration.'
        });
    }
});
// ===============================
// FITZONE LOGIN API
// ===============================

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            error: 'Email and password are required.'
        });
    }

    const sql = `
        SELECT user_id, username, email, password_hash,
               role, member_id, trainer_id
        FROM Users
        WHERE email = ?
    `;

    db.query(sql, [email.trim()], async (err, results) => {
        if (err) {
            console.error('Login error:', err);
            return res.status(500).json({
                error: 'Login failed. Please try again.'
            });
        }

        if (results.length === 0) {
            return res.status(401).json({
                error: 'Invalid email or password.'
            });
        }

        const user = results[0];

        try {
            const passwordMatches = await bcrypt.compare(
                password,
                user.password_hash
            );

            if (!passwordMatches) {
                return res.status(401).json({
                    error: 'Invalid email or password.'
                });
            }

            req.session.regenerate((sessionError) => {
                if (sessionError) {
                    return res.status(500).json({
                        error: 'Could not create login session.'
                    });
                }

                req.session.user = {
                    user_id: user.user_id,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    member_id: user.member_id,
                    trainer_id: user.trainer_id
                };

                req.session.save((saveError) => {
                    if (saveError) {
                        return res.status(500).json({
                            error: 'Could not save login session.'
                        });
                    }

                    res.json({
                        message: 'Login successful!',
                        user: {
                            username: user.username,
                            role: user.role
                        }
                    });
                });
            });

        } catch (error) {
            console.error('Password verification error:', error);
            res.status(500).json({
                error: 'Something went wrong during login.'
            });
        }
    });
});
// Check whether user is logged in
app.get('/api/auth/me', (req, res) => {

    if (!req.session.user) {
        return res.status(401).json({
            error: 'You are not logged in.'
        });
    }

    res.json({
        user: req.session.user
    });

});
// Logout API
app.post('/api/auth/logout', (req, res) => {

    req.session.destroy((err) => {

        if (err) {
            return res.status(500).json({
                error: 'Could not log out.'
            });
        }

        res.clearCookie('fitzone.sid');

        res.json({
            message: 'Logged out successfully!'
        });

    });

});
// Check whether user is logged in
function requireLogin(req, res, next) {

    if (!req.session.user) {
        return res.status(401).json({
            error: 'Please login first.'
        });
    }

    next();
}
// Check user role
function requireRole(...roles) {

    return (req, res, next) => {

        if (!req.session.user) {
            return res.status(401).json({
                error: 'Please login first.'
            });
        }

        if (!roles.includes(req.session.user.role)) {
            return res.status(403).json({
                error: 'You do not have permission to access this resource.'
            });
        }

        next();
    };
}
// Allow only logged-in users to open the dashboard
app.get('/index.html', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
// Test route
app.get('/api/status', (req, res) => {
    res.json({ message: 'Gym Management System Backend is Running!' });
});

// Get all members

/* GET all members */
app.get('/api/members', requireRole('admin'), (req, res) => {
    db.query(
        'SELECT * FROM Members ORDER BY member_id DESC',
        (err, results) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(results);
        }
    );
});

/* Get all memberships with member and plan details */
app.get('/api/memberships', (req, res) => {
    const sql = `
        SELECT
            m.membership_id,
            m.member_id,
            mem.name AS member_name,
            m.plan_id,
            p.plan_name,
            m.start_date,
            m.end_date,
            m.status
        FROM Memberships m
        JOIN Members mem ON m.member_id = mem.member_id
        JOIN MembershipPlans p ON m.plan_id = p.plan_id
        ORDER BY m.membership_id DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

app.post('/api/memberships', (req, res) => {
  const { member_id, plan_id, start_date } = req.body;

  if (!member_id || !plan_id || !start_date) {
    return res.status(400).json({
      message: 'Please select a member, plan, and start date.'
    });
  }

  const sql = `
    INSERT INTO Memberships
      (member_id, plan_id, start_date, end_date, status)
    SELECT
      ?, ?, ?, DATE_ADD(?, INTERVAL duration_months MONTH), 'Active'
    FROM MembershipPlans
    WHERE plan_id = ?
  `;

  db.query(
    sql,
    [member_id, plan_id, start_date, start_date, plan_id],
    (err, result) => {
      if (err) {
        console.error('Error adding membership:', err);
        return res.status(500).json({
          message: 'Could not add membership.'
        });
      }

      if (result.affectedRows === 0) {
        return res.status(400).json({
          message: 'Selected membership plan was not found.'
        });
      }

      res.status(201).json({
        message: 'Membership added successfully!',
        membership_id: result.insertId
      });
    }
  );
});


/* ADD a new member */
app.post('/api/members', requireRole('admin'), (req, res) => {
    const { name, email, phone, join_date } = req.body;

    if (!name || !email || !join_date) {
        return res.status(400).json({
            error: 'Name, email and join date are required.'
        });
    }

    const sql = `
        INSERT INTO Members (name, email, phone, join_date)
        VALUES (?, ?, ?, ?)
    `;

    db.query(
        sql,
        [name.trim(), email.trim(), phone || null, join_date],
        (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({
                        error: 'This email is already registered.'
                    });
                }
                return res.status(500).json({ error: err.message });
            }

            res.status(201).json({
                message: 'Member added successfully!',
                member_id: result.insertId
            });
        }
    );
});

/* DELETE a member */
app.delete('/api/members/:id', requireRole('admin'), (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({ error: 'Invalid member ID.' });
    }

    db.query(
        'DELETE FROM Members WHERE member_id = ?',
        [id],
        (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Member not found.' });
            }

            res.json({ message: 'Member deleted successfully!' });
        }
    );
});


// Get all trainers
app.get('/api/trainers', (req, res) => {
    db.query('SELECT * FROM Trainers', (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// Get all membership plans
app.get('/api/plans', (req, res) => {
    db.query('SELECT * FROM MembershipPlans', (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

/* Get all payments with member and plan details */
app.get('/api/payments', (req, res) => {
    const sql = `
        SELECT
            p.payment_id,
            p.membership_id,
            m.name AS member_name,
            mp.plan_name,
            p.amount,
            p.payment_date,
            p.payment_method
        FROM Payments p
        JOIN Memberships ms ON p.membership_id = ms.membership_id
        JOIN Members m ON ms.member_id = m.member_id
        JOIN MembershipPlans mp ON ms.plan_id = mp.plan_id
        ORDER BY p.payment_id DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});


/* Get fitness activities with member and trainer names */
app.get('/api/activities', (req, res) => {
    const sql = `
        SELECT
            fa.activity_id,
            m.name AS member_name,
            t.name AS trainer_name,
            fa.activity_name,
            fa.activity_date,
            fa.duration_minutes,
            fa.calories_burned
        FROM FitnessActivities fa
        JOIN Members m ON fa.member_id = m.member_id
        LEFT JOIN Trainers t ON fa.trainer_id = t.trainer_id
        ORDER BY fa.activity_id DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

app.put('/api/members/:id', requireRole('admin'), (req, res) => {
  const { name, email, phone, join_date } = req.body;
  const id = req.params.id;

  if (!name || !email || !join_date) {
    return res.status(400).json({
      error: 'Name, email, and join date are required.'
    });
  }

  const sql = `
    UPDATE members
    SET name = ?, email = ?, phone = ?, join_date = ?
    WHERE member_id = ?
  `;

  db.query(sql, [name, email, phone || null, join_date, id],
    (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({
            error: 'This email is already registered.'
          });
        }

        console.error(err);
        return res.status(500).json({
          error: 'Failed to update member.'
        });
      }

      if (result.affectedRows === 0) {
        return res.status(404).json({
          error: 'Member not found.'
        });
      }

      res.json({ message: 'Member updated successfully!' });
    }
  );
});


// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
