import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { PORT } from './config.js';
import { SECRET_KEY } from './config.js';
import { UserRepository } from './user-repository.js';

const app = express();
app.set('view engine', 'ejs')
app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
    const token = req.cookies.access_token;
    req.session = { user: null };

    try {
        const data = jwt.verify(token, SECRET_KEY);
        req.session.user = data;
    } catch {}

    next();
});

app.get('/', (req, res) => {
    const { user } = req.session;
    if (!user) return res.send('Hello, World!');
    res.send(`Hello, ${user.username}!`);
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await UserRepository.login({ username, password });
        const token = jwt.sign(
            { id: user._id, username: user.username },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        res
            .cookie(
                'access_token',
                token,
                {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 1000 * 60 * 60
                }
            )
            .send({ user });
    } catch (error) {
        res.status(401).send(error.message);
    }
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const id = await UserRepository.create({ username, password });
        res.send(id);
    } catch (error) {
        res.status(400).send(error.message);
    }
});

app.post('/logout', (req, res) => {
    res
        .clearCookie('access_token')
        .send('Logout successful.');
});

app.get('/protected', (req, res) => {
    const { user } = req.session;
    if (!user) return res.status(403).send('Access not authorized.');
    res.render('protected', user);
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});