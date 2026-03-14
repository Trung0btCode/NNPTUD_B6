let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')
let userController = require("../controllers/users")

let publicKey = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.key'))

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token || !token.startsWith('Bearer ')) {
                return res.status(401).send({ message: "ban chua dang nhap" })
            }
            token = token.split(" ")[1];
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
            let user = await userController.FindUserById(result.id);
            if (!user) {
                return res.status(401).send({ message: "ban chua dang nhap" })
            }
            req.user = user;
            next();
        } catch (error) {
            return res.status(401).send({ message: "ban chua dang nhap" })
        }
    }
}