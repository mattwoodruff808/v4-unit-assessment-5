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
    login: async (req, res) => {
        const {username, password} = req.body;
        const db = req.app.get('db');

        const [foundUser] = await db.user.find_user_by_username({username});
        if (!foundUser){
            return res.status(404).send('Username not found');
        }

        const authenticated = bcrypt.compareSync(password, foundUser.password);
        if (!authenticated){
            return res.status(401).send('Password is incorrect');
        }

        delete foundUser.password;

        req.session.user = foundUser;
        res.status(202).send(req.session.user);
    },
    logout: (req, res) => {
        req.session.destroy();
        res.sendStatus(200);
    },
    getUser: (req, res) => {
        if (req.session.user){
            res.status(200).send(req.session.user);
        } else {
            res.sendStatus(404);
        }
    }
}