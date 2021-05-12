const bcrypt = require('bcryptjs')

module.exports = {
    register: async (req, res) => {
        const db = req.app.get('db')
        const {email, password} = req.body
        const foundUser = await db.check_user_exists(email)
        if(foundUser[0]){
            return res.status(409).send("Email already exists")
        }
        const salt = bcrypt.genSaltSync(10)
        const hash = bcrypt.hashSync(password, salt)
        const createdUser = await db.create_user(email, hash)
        delete createdUser[0].user_password
        req.session.user = createdUser[0]
        res.status(200).send(req.session.user)
    },
    login: async (req, res) => {
        const db = req.app.get('db')
        const {email, password} = req.body
        const foundUser = await db.check_user_exists(email)
        if(!foundUser[0]){
            return res.status(401).send('Email or Password are incorrect')
        }
        const authenticated = bcrypt.compareSync(password, foundUser[0].user_password)
        if(authenticated){
            delete foundUser[0].user_password
            req.session.user = foundUser[0]
            res.status(200).send(req.session.user)
        } else {
            return res.status(401).send('Incorrect email or password')
        }
    },
    logout: (req, res) => {
        req.session.destroy();
        res.sendStatus(200)
    }
}