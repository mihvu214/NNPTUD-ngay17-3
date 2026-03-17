let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')

// Đọc public key RS256
const publicKey = fs.readFileSync('./keys/public.pem', 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        let key = req.headers.authorization;
        
        // Xử lý Bearer token từ Authorization header
        if (key && key.startsWith('Bearer ')) {
            key = key.substring(7); // Bỏ "Bearer " prefix
        }
        
        if (!key) {
            if (req.cookies.LOGIN_NNPTUD_S3) {
                key = req.cookies.LOGIN_NNPTUD_S3;
            } else {
                res.status(404).send("ban chua dang nhap")
                return;
            }

        }

        try {
            // Verify sử dụng public key và RS256
            let result = jwt.verify(key, publicKey, { algorithms: ['RS256'] })
            if (result.exp * 1000 < Date.now()) {
                res.status(404).send("ban chua dang nhap")
                return;
            }
            let user = await userController.GetUserById(result.id);
            if (!user) {
                res.status(404).send("ban chua dang nhap")
                return;
            }
            req.user = user;
            next();
        } catch (error) {
            res.status(404).send("ban chua dang nhap")
            return;
        }

    }
}