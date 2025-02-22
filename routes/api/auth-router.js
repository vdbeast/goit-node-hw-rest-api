const express = require('express')

const authControllers = require('../../controllers/auth-controller.js')

const isEmptyBody = require('../../middlewares/isEmptyBody.js')
const validateBody = require('../../decorators/validateBody.js')
const userSchema = require('../../models/User.js')
const authenticate = require('../../middlewares/authenticate.js')
const upload = require('../../middlewares/upload.js')
const resize = require('../../middlewares/resizeAvatars.js')

const userSignupValidate = validateBody(userSchema.userSignupSchema);
const userSigninValidate = validateBody(userSchema.userSigninSchema);
const userEmailValidate = validateBody(userSchema.userEmailSchema);

const authRouter = express.Router()

authRouter.post('/users/register', upload.single("avatarURL"), isEmptyBody, userSignupValidate, authControllers.signup)

authRouter.get('/users/verify/:verificationToken', authControllers.verify)

authRouter.post('/users/verify', userEmailValidate, authControllers.resendVerifyEmail)

authRouter.post('/users/login', isEmptyBody, userSigninValidate, authControllers.signin)

authRouter.get('/users/current', authenticate, authControllers.getCurrent)

authRouter.post('/users/logout', authenticate, authControllers.logout)

authRouter.patch('/users/avatars', upload.single("avatarURL"), resize, authenticate, authControllers.updateAvatars)

module.exports = authRouter