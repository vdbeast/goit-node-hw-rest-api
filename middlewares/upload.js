const multer = require("multer");
const path = require("path");

const destination = path.resolve("temp")

const storage = multer.diskStorage({
    destination,
    filename: (req, file, cb) => {
        const uniqueSuffix = `${Date.now()}_${Math.random(Math.round() * 1e9)}`;
        const filename = `${uniqueSuffix}_${file.originalname}`;

        cb(null, filename);
    },
});

const limits = {
    fileSize: 5 * 1024 * 1024,
};

const fileFilter = (req, file, cb) => {
    if (file.originalname.split(".").pop() === "exe") {
        cb(new Error("File extension not allow"));
    }
    cb(null, true);
};

const upload = multer({
    storage,
    limits,
    fileFilter
})

module.exports = upload;