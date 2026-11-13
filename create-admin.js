require('dotenv').config();

const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const readline = require('readline');

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function createAdmin() {
    const ask = (question) =>
        new Promise(resolve => rl.question(question, resolve));

    try {
        const username = await ask('Enter admin username: ');
        const email = await ask('Enter admin email: ');
        const password = await ask('Enter admin password: ');

        if (!username.trim() || !email.trim() || !password) {
            console.log('All fields are required.');
            return;
        }

        if (password.length < 8) {
            console.log('Password must contain at least 8 characters.');
            return;
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const sql = `
            INSERT INTO Users (username, email, password_hash, role)
            VALUES (?, ?, ?, 'admin')
        `;

        db.query(
            sql,
            [username.trim(), email.trim(), passwordHash],
            (err, result) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        console.log('This username or email already exists.');
                    } else {
                        console.log('Error:', err.message);
                    }
                } else {
                    console.log('Admin account created successfully!');
                    console.log('Admin User ID:', result.insertId);
                }

                db.end();
                rl.close();
            }
        );
    } catch (error) {
        console.log('Error:', error.message);
        db.end();
        rl.close();
    }
}

db.connect((err) => {
    if (err) {
        console.log('Database connection failed:', err.message);
        rl.close();
        return;
    }

    createAdmin();
});