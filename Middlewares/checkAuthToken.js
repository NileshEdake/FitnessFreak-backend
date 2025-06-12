const jwt = require('jsonwebtoken');

function checkAuth(req, res, next) {
    const cookieToken = req.cookies.authToken;
    const headerToken = req.headers.authorization?.split(" ")[1]; // 👈 support Authorization header
    const authToken = cookieToken || headerToken; // 👈 choose one

    if (!authToken) {
        return res.status(401).json({ message: 'Authentication failed: No token provided', ok: false });
    }

    jwt.verify(authToken, process.env.JWT_SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Authentication failed: Invalid token', ok: false });
        } else {
            req.userId = decoded.userId;
            next();
        }
    });
}

module.exports = checkAuth;
