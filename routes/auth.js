const express = require("express");
const router = new express.Router();
const User = require('../models/user');
const ExpressError = require("../expressError");
const { SECRET_KEY } = require("../config");
const jwt = require("jsonwebtoken");
/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/
router.post("/login", async function (req, res, next) {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            throw new ExpressError("Missing username/password", 400);
        }
        if (await User.authenticate(username, password)) {
            await User.updateLoginTimestamp(username);
            const token = jwt.sign({ username }, SECRET_KEY);
            return res.json({ token })
        } else {
            throw new ExpressError('Invalid username/password', 400);
        }
    } catch (err) {
        return next(err);
    }
})


/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async function (req, res, next) {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if (!username || !password || !first_name || !last_name || !phone) {
            throw new ExpressError("Missing required information", 400);
        }
        await User.register({ username, password, first_name, last_name, phone });
        const token = jwt.sign({ username }, SECRET_KEY);
        return res.json({ token });
    } catch (err) {
        return next(err)
    };
});

module.exports = router;