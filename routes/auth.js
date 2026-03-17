var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, ChangePasswordValidator, validationResult } = require('../utils/validatorHandler')
let { CheckLogin } = require('../utils/authHandler')
let jwt = require('jsonwebtoken')
let fs = require('fs')

// Đọc private key RS256
const privateKey = fs.readFileSync('./keys/private.pem', 'utf8');

router.post('/register', RegisterValidator, validationResult, async function (req, res, next) {
    try {
        let newItem = await userController.CreateAnUser(
            req.body.username, req.body.password, req.body.email,
            "69af870aaa71c433fa8dda8e"
        )
        res.send(newItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let result = await userController.FindUserByUsername(username);
        if (!result) {
            res.status(403).send("sai thong tin dang nhap");
            return;
        }
        if (result.lockTime > Date.now()) {
            res.status(404).send("ban dang bi ban");
            return;
        }
        result = await userController.CompareLogin(result, password);
        if (!result) {
            res.status(403).send("sai thong tin dang nhap");
            return;
        }
        // Tạo JWT sử dụng RS256 và private key
        let token = jwt.sign({
            id: result._id
        }, privateKey, {
            expiresIn: '1d',
            algorithm: 'RS256'
        })
        res.cookie("LOGIN_NNPTUD_S3", token, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true
        })
        res.send(token)

    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})
router.get('/me', CheckLogin, function (req, res, next) {
    let user = req.user;
    res.send(user)
})

// Endpoint changePassword - yêu cầu đăng nhập
router.post('/changePassword', CheckLogin, ChangePasswordValidator, validationResult, async function (req, res, next) {
    try {
        let { oldPassword, newPassword } = req.body;
        let userId = req.user._id;

        // Lấy user từ database
        let user = await userController.GetUserById(userId);
        if (!user) {
            res.status(404).send("User not found");
            return;
        }

        // Kiểm tra password cũ
        let isPasswordValid = await userController.CompareLogin(user, oldPassword);
        if (!isPasswordValid) {
            res.status(403).send("Old password is incorrect");
            return;
        }

        // Cập nhật password mới
        let updatedUser = await userController.UpdateUserPassword(userId, newPassword);
        
        res.send({
            message: "Password changed successfully",
            user: updatedUser
        });

    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})

router.post('/logout', CheckLogin, function (req, res, next) {
    res.cookie("LOGIN_NNPTUD_S3", "", {
        maxAge: 0,
        httpOnly: true
    })
    res.send("da logout ")
})

module.exports = router;