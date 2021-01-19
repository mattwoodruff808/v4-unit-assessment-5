const bcrypt = require('bcryptjs');

module.exports = {
    register: async (req, res) => {
        const {username, password} = req.body;
        const db = req.app.get('db');

        const [foundUser] = await db.user.find_user_by_username({username});
        if (foundUser){
            return res.status(400).send('Username already in use');
        }

        let salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);
        const [newUser] = await db.user.create_user([username, hash, `https://robohash.org/${username}.png`])

        req.session.user = newUser;
        res.status(201).send(req.session.user);
    },
    login: (req, res) => {

    },
    logout: (req, res) => {

    },
    getUser: (req, res) => {

    }
}