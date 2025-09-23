import app from "../index.js";
import request from "supertest";


describe('Auth and Todos API', () => {
    let token='';
    let todoId = null;
    
    it('should register a new user', async () => {
        const res = await request(app)
            .post('/register')
            .send({
                username: 'testuser',
                email: 'testuser@example.com',
                password: 'testpassword'
            });
        expect(res.statusCode).toBe(201);
    });

    it('should login the user and return a token', async () => {
        const res = await request(app)
            .post('/login')
            .send({
                email: 'testuser@example.com',
                password: 'testpassword'
            });
        expect(res.statusCode).toBe(200);
        expect(res.body).toHaveProperty('token');
        token = res.body.token;
    });

    it("should create a new todo", async () => {
        const res = await request(app)
            .post('/todo')
            .set('Authorization', `Bearer ${token}`)
            .send({
                title: 'Test Todo',
                description: 'This is a test todo'
            });
        expect(res.statusCode).toBe(201);
        expect(res.body).toHaveProperty('taskid');
        todoId = res.body.taskid;
    });

    it("should get all todos for that user", async () => {
        const res = await request(app)
            .get('/todos')
            .set('Authorization', `Bearer ${token}`);
        expect(res.statusCode).toBe(200);
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(res.body.data.length).toBeGreaterThan(0);
    });

    it('Updated todo for that user', async () => {
        console.log('Using taskid:', todoId);
        const res = await request(app)
            .put(`/todo/${todoId}`)
            .set('Authorization', `Bearer ${token}`)
            .send({
                title: 'Updated Test Todo',
                description: 'This is an updated test todo'
            });
        expect(res.statusCode).toBe(200);
        expect(res.body.title).toBe('Updated Test Todo');
        expect(res.body.description).toBe('This is an updated test todo');
    });

}); 
