import express from 'express';
import con from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from 'bcrypt';

const router = express.Router();

// Employee Login Route
router.post("/employee_login", (req, res) => {
    const sql = "SELECT * FROM employee WHERE email = ?";
    
    con.query(sql, [req.body.email], (err, result) => {
        if (err) return res.json({ loginStatus: false, Error: "Query error" });
        
        if (result.length > 0) {
            bcrypt.compare(req.body.password, result[0].password, (err, response) => {
                if (err) return res.json({ loginStatus: false, Error: "Error verifying password" });

                if (response) {
                    const token = jwt.sign(
                        { role: "employee", email: result[0].email, id: result[0].id },
                        "jwt_secret_key",
                        { expiresIn: "1d" }
                    );

                    // Securely set the cookie
                    res.cookie('token', token, { httpOnly: true, secure: false });
                    return res.json({ loginStatus: true, id: result[0].id });
                } else {
                    return res.json({ loginStatus: false, Error: "Wrong Password" });
                }
            });
        } else {
            return res.json({ loginStatus: false, Error: "Wrong email or password" });
        }
    });
});

// Get Employee Details by ID
router.get('/detail/:id', (req, res) => {
    const id = req.params.id;
    const sql = "SELECT * FROM employee WHERE id = ?";

    con.query(sql, [id], (err, result) => {
        if (err) return res.json({ Status: false, Error: "Query error" });
        return res.json(result);
    });
});

// Employee Logout Route
router.get('/logout', (req, res) => {
    res.clearCookie('token', { httpOnly: true, secure: false });
    return res.json({ Status: true, Message: "Logged out successfully" });
});

export { router as EmployeeRouter };
