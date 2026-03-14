let express = require('express')
let router = express.Router()
let userController = require('../controllers/users')
let { RegisterValidator, validatedResult } = require('../utils/validator')
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')
const { check } = require('express-validator')
const { checkLogin } = require('../utils/authHandler')

let privateKey = fs.readFileSync(path.join(__dirname, '..', 'keys', 'private.key'))

router.post('/register', RegisterValidator, validatedResult, async function (req, res, next) {
    let { username, password, email } = req.body;
    let hashed = await bcrypt.hash(password, 10);
    let newUser = await userController.CreateAnUser(
        username, hashed, email, '69b2763ce64fe93ca6985b56'
    )
    res.send({
        message: 'register success',
        user: { id: newUser._id, username: newUser.username, email: newUser.email }
    })
})

router.post('/login', async function (req, res, next) {
    let { username, password } = req.body;
    let user = await userController.FindUserByUsername(username);
    if (!user) {
        return res.status(404).send({ message: "thong tin dang nhap khong dung" })
    }
    if (!user.lockTime || user.lockTime < Date.now()) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save();
            let token = jwt.sign({
                id: user._id,
            }, privateKey, {
                algorithm: 'RS256',
                expiresIn: '1h'
            })
            return res.send({ token })
        } else {
            user.loginCount++;
            if (user.loginCount == 3) {
                user.loginCount = 0;
                user.lockTime = new Date(Date.now() + 60 * 60 * 1000)
            }
            await user.save();
            return res.status(404).send({ message: "thong tin dang nhap khong dung" })
        }
    } else {
        return res.status(403).send({ message: "user dang bi ban" })
    }
})

router.post('/change-password', checkLogin, [
    check('oldpassword').notEmpty().withMessage('oldpassword khong duoc de trong'),
    check('newpassword').notEmpty().withMessage('newpassword khong duoc de trong').bail().isStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minNumbers: 1,
        minSymbols: 1,
        minUppercase: 1
    }).withMessage('newpassword phai dai it nhat 8, co hoa, thuong, so, ky tu dac biet')
], validatedResult, async function (req, res, next) {
    let { oldpassword, newpassword } = req.body;
    let user = req.user;
    if (!bcrypt.compareSync(oldpassword, user.password)) {
        return res.status(400).send({ message: 'oldpassword khong dung' })
    }
    user.password = await bcrypt.hash(newpassword, 10);
    await user.save();
    res.send({ message: 'doi mat khau thanh cong' });
})

router.get('/me', checkLogin, function (req, res, next) {
    res.send(req.user)
})

module.exports = router;