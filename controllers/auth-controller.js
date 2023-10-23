const fs = require('fs/promises')
const path = require('path')
const gravatar = require("gravatar")
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken");
const { User } = require('../models/User.js')
const HttpError = require("../helpers/HttpError.js");
const ctrlWrapper = require('../decorators/ctrlWrapper.js');

const avatarsPath = path.resolve("public", "avatars");

require("dotenv").config();
const { JWT_SECRET } = process.env;

const signup = async (req, res) => {
    const { email, password } = req.body;

    let avatarURL = gravatar.url(email, { s: "200", r: "pg", d: "404" });
    if (req.file) {
        const { path: oldPath, filename } = req.file;
        const newPath = path.join(avatarsPath, filename);
        await fs.rename(oldPath, newPath);
        avatarURL = path.join("avatars", filename);
    };

    const user = await User.findOne({ email })
    if (user) {
        throw HttpError(409, `${email} already in use`);
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({ ...req.body, avatarURL, password: hashPassword });
    
    res.status(201).json({
        email: newUser.email,
        subscription: newUser.subscription,
        avatarURL: newUser.avatarURL,
    });
}

const signin = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email })

    if (!user) {
        throw HttpError(401, `Email or password is wrong`);
    }

    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!passwordCompare) {
        throw HttpError(401, `Email or password is wrong`);
    }

    const payload = {
        id: user._id,
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "24h" });
    await User.findByIdAndUpdate(user._id, { token });

    res.json({
        token,
        user: {
            email: user.email,
            subscription: user.subscription,
            avatarURL: user.avatarURL,
        }
    })
}

const getCurrent = async (req, res) => {
    const { email, subscription, avatarURL } = req.user;
    res.json({
        email,
        subscription,
        avatarURL,
    });
}

const logout = async (req, res) => {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: "" });

    res.status(204).send();
}

const updateAvatars = async (req, res) => {
    const { token } = req.user;
    let avatarURL = req.user.avatarURL;
    if (req.file) {
        const { path: oldPath, filename } = req.file;
        const newPath = path.join(avatarsPath, filename);
        await fs.rename(oldPath, newPath);
        avatarURL = path.join("avatars", filename);
    }

    const updatedUser = await User.findOneAndUpdate(
        { token },
        { avatarURL },
        { new: true }
    );

    if (!updatedUser) {
        throw HttpError(404, "User not found");
    }

    res.json({
        avatarURL: updatedUser.avatarURL,
    });
}

module.exports = {
    signup: ctrlWrapper(signup),
    signin: ctrlWrapper(signin),
    getCurrent: ctrlWrapper(getCurrent),
    logout: ctrlWrapper(logout),
    updateAvatars: ctrlWrapper(updateAvatars)
}