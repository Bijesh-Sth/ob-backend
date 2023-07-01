const jwt = require("jsonwebtoken");

const authGuard = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(404).json({ error: "Authorization header not found." });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
        return res.status(404).json({ error: "No header token found!" });
    }

    try {
        const decodedUser = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decodedUser;
        console.log(req.user);
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).json({ error: "Invalid token!" });
    }
};

module.exports = authGuard;
