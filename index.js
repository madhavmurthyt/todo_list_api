import express from 'express';
import sql from './connectToDB.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit'; 


const app = express();
const PORT = process.env.PORT || 3033;

app.use(express.json()); 
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 1 minute
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'your_refresh_token_secret';

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Missing Details' });
    }
    try {
        const [user] = await sql`SELECT * FROM users WHERE email = ${email}`;
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const accessToken = jwt.sign({ email: user.email, password: user.password }, JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ email: user.email, password: user.password }, REFRESH_TOKEN_SECRET, { expiresIn: '1h' });
        res.status(200).json({ "token": accessToken, "refreshToken": refreshToken });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/refresh',async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(400).json({ error: 'Missing Details' });
    }
    try {
        const payload = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
        const accessToken = jwt.sign({ email: payload.email, password: payload.password }, JWT_SECRET, { expiresIn: '15m' });
        res.json({ "token": accessToken });
    } catch (err) {
        return res.status(401).json({ error: 'Invalid refresh token' });
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Missing Details' });
    }

    const result = await sql`SELECT * FROM users WHERE email = ${email} `;
    if (result.length > 0) {
        return res.status(409).json({ error: 'User already exists' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await sql`INSERT INTO users (username, email, password) VALUES (${username}, ${email}, ${hashedPassword}) RETURNING email, password`;
        res.status(201).json("User registered successfully");
    }
    catch (err) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/todo', async (req, res) => {
    const { title, description } = req.body;
    const { authorization } = req.headers;
    if(authorization && authorization.startsWith('Bearer ')){
        const token = authorization.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            const email = decoded.email;
            if (!email) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
            
            const user = await sql`SELECT * FROM users WHERE email = ${email}`;
            const userid = user[0].userid

            if (!title || !description) {
                return res.status(400).json({ error: 'Missing Details' });
            }
            const result = await sql`INSERT INTO todos (userid, title, description) VALUES (${userid}, ${title}, ${description}) RETURNING *`;
            res.status(201).json(result[0]);
        } catch (err) {
            return res.status(401).json({ error: "Internal Error" });
        }
    } else {
        return res.status(401).json({ error: 'Unauthorized' });
    }
});

app.put('/todo/:id', async (req, res) => {
    const { id } = req.params;
    const { title, description } = req.body;
    const { authorization } = req.headers;
    if(authorization && authorization.startsWith('Bearer ')){
        const token = authorization.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
                return res.status(403).json({ error: 'Unauthorized' });
            }
            const email = decoded.email;
            if (!email) {
                return res.status(403).json({ error: 'Unauthorized' });
            }
            const todo = await sql`select * from todos where userid = (SELECT userid FROM users WHERE email = ${email}) and taskid = ${id}`;
            if(todo.length > 0) {
                const userid = todo[0].userid
                if (!title || !description) {
                    return res.status(400).json({ error: 'Missing Details' });
                }
                console.log("PRINT->>>>>> "+title, description, id, userid);
                const result = await sql`UPDATE todos SET title = ${title}, description = ${description} WHERE taskid = ${id} AND userid = ${userid} RETURNING title, description`;
                    return res.status(200).json(result[0]);
            }
            return res.status(403).json({ error: 'Unauthorized' });
        } catch(err) {
                    return res.status(401).json({ error: "Internal Error" });

        }
    }
});


app.delete('/todo/:id', async(req,res) => {
    const { id } = req.params;
    const { authorization } = req.headers;
     if(authorization && authorization.startsWith('Bearer ')){
        const token = authorization.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
                return res.status(403).json({ error: 'Unauthorized' });
            }
            const email = decoded.email;
            if (!email) {
                return res.status(403).json({ error: 'Unauthorized' });
            }

            const todo = await sql`select * from todos where userid = (SELECT userid FROM users WHERE email = ${email}) and taskid = ${id}`;
            if(todo.length > 0) {
                const userid = todo[0].userid
                const result = await sql`DELETE FROM todos WHERE taskid = ${id} AND userid = ${userid} RETURNING taskid`;
                if(result.length > 0) {
                    return res.status(204).json("Deleted");
                }
            }
            return res.status(403).json({ error: 'Unauthorized' });
         } catch(err) {
                    return res.status(401).json({ error: "Internal Error" });
         }
    }        
});

app.get('/todos', async (req, res) => {
    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 10;
    let term = req.query.term;
    const offset = (page - 1) * limit;
    
    const { authorization } = req.headers;
    if(authorization && authorization.startsWith('Bearer ')){
        const token = authorization.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!decoded) {
                return res.status(403).json({ error: 'Unauthorized' });
            }
            const email = decoded.email;
            if (!email) {
                return res.status(403).json({ error: 'Unauthorized' });
            }
            const user = await sql`SELECT userid FROM users WHERE email = ${email}`;
            if(!user[0]) return res.status(403).json({ error: 'Unauthorized' });
            const userid = user[0].userid;

            const totalResult = await sql`SELECT COUNT(*) as count FROM todos WHERE userid = ${userid}`;
        
            const total = parseInt(totalResult[0].count);
            if(total === 0) {
                return res.status(403).json({ error: 'Unauthorized' });
            }
           
            let todos = []
            if(term){
                const pattern = `%${term}%`;
                todos = await sql`
                    SELECT taskid, title, description
                     FROM todos 
                     WHERE userid = ${userid} 
                        AND (title ILIKE ${pattern} OR description ILIKE ${pattern})
                     ORDER BY taskid ASC
                     LIMIT ${limit} OFFSET ${offset}
                    `;
        
            } else {
                todos = await sql`
                    SELECT taskid, title, description
                     FROM todos 
                     WHERE userid = ${userid} 
                     ORDER BY taskid ASC
                     LIMIT ${limit} OFFSET ${offset}
                    `;
            }
                 res.status(200).json({
                        data: todos,
                        page,
                        limit,
                        total
                    });

                  
        } catch(err) {
                    return res.status(401).json({ error: "Internal Error" });
        }
    } else {
        return res.status(401).json({ error: 'Unauthorized' });
    }
});

export default app;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});