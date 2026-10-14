import { MongoClient, ObjectId } from 'mongodb' // Documentación CRUD: https://mongodb.github.io/node-mongodb-native/6.2/
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import "express-async-errors"
import rateLimit from "express-rate-limit"
import swaggerUi from "swagger-ui-express"
import swaggerDocument from "./openapi.json" with { type: "json" }

const SECRET_KEY = process.env.JWT_SECRET
const REFRESH_KEY = process.env.JWT_REFRESH_SECRET
const app = express()



app.use(express.json())  // IMPORTANTE: SOPORTE PARA JSON
app.use(cors())          // Para habilitar CORS 
app.set('trust proxy', 1)

const limitMessage = { message: "Demasiadas peticiones, inténtalo más tarde" }
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, message: limitMessage }))
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, message: limitMessage })

const swaggerCdn = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5"
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
    customCssUrl: `${swaggerCdn}/swagger-ui.css`,
    customJs: [`${swaggerCdn}/swagger-ui-bundle.js`, `${swaggerCdn}/swagger-ui-standalone-preset.js`]
}))

function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(" ")[1]; // formato "Bearer <token>"

    if (!token) return response.status(403).json({ message: "Token requerido" });

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        return response.status(403).json({ message: "Token inválido" });
    }
}

// REGISTER
app.post('/api/register', authLimiter, async (request, response) => {
    if (!request.is('json'))
        return response.status(400).json({ message: 'Debes proporcionar datos JSON' })

    const { nombre, edad, password } = request.body
    if (!nombre || !password)
        return response.status(400).json({ message: "Nombre y contraseña requeridos" })

    const collection = client.db(DB_NAME).collection(USERS)

    if (await collection.findOne({ nombre }))
        return response.status(409).json({ message: "El usuario ya existe" })

    const hash = await bcrypt.hash(password, 10)
    const results = await collection.insertOne({ nombre, edad, password: hash })

    response.status(201).json({ _id: results.insertedId, nombre, edad })
})

// LOGIN
app.post('/api/login', authLimiter, async (request, response) => {
    if (!request.is('json'))
        return response.status(400).json({ message: 'Debes proporcionar datos JSON' })

    const { nombre, password } = request.body

    const user = await client.db(DB_NAME).collection(USERS).findOne({ nombre })

    if (!user) {
        return response.status(401).json({ message: "Usuario no encontrado" })
    }

    const correctPassword = await bcrypt.compare(password ?? "", user.password ?? "")

    if (!correctPassword) {
        return response.status(401).json({ message: "Contraseña incorrecta" })
    }

    const payload = { id: user._id.toString(), nombre: user.nombre }
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '5m' })
    const refreshToken = jwt.sign(payload, REFRESH_KEY, { expiresIn: '7d' })

    await client.db(DB_NAME).collection(REFRESH_TOKENS).insertOne({ token: refreshToken })

    response.json({ token, refreshToken })
})

// REFRESH
app.post('/api/refresh', authLimiter, async (request, response) => {
    const { refreshToken } = request.body ?? {}
    if (!refreshToken)
        return response.status(400).json({ message: "Refresh token requerido" })

    const collection = client.db(DB_NAME).collection(REFRESH_TOKENS)

    if (!await collection.findOne({ token: refreshToken }))
        return response.status(403).json({ message: "Refresh token inválido" })

    try {
        const { id, nombre } = jwt.verify(refreshToken, REFRESH_KEY)
        const token = jwt.sign({ id, nombre }, SECRET_KEY, { expiresIn: '5m' })
        response.json({ token })
    } catch (err) {
        await collection.deleteOne({ token: refreshToken })
        response.status(403).json({ message: "Refresh token expirado" })
    }
})

// LOGOUT
app.post('/api/logout', async (request, response) => {
    const { refreshToken } = request.body ?? {}
    await client.db(DB_NAME).collection(REFRESH_TOKENS).deleteOne({ token: refreshToken })
    response.json({ message: "Sesión cerrada" })
})

const PORT = process.env.PORT ?? 3000
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const DB_NAME = process.env.DB_NAME ?? 'api'
const USERS = 'users'
const PRODUCTS = 'products'
const REFRESH_TOKENS = 'refresh_tokens'

const client = new MongoClient(DB_URL)

app.get("/", (request, response) => {
    response.redirect("/api-docs")
})


// GET
app.get('/api/users', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const results = await collection.find({}, { projection: { password: 0 } }).toArray()

    response.status(200).json(results)
})

// POST 
app.post('/api/users', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const { nombre, edad } = request.body
    const results = await collection.insertOne({ nombre, edad });

    return response.status(200).json(results)
})

// GET 
app.get('/api/users/:id', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const { id } = request.params
    const results = await collection.find({ _id: new ObjectId(id) }, { projection: { password: 0 } }).toArray

    response.status(200).json(results)
})

// PUT
app.put('/api/users/:id', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const { id } = request.params
    const { nombre, edad } = request.body
    const results = await collection.updateOne({ _id: new ObjectId(id) }, { $set: { nombre, edad } });

    response.status(200).json(results)
})

// DELETE
app.delete('/api/users/:id', verifyToken, async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const { id } = request.params
    const results = await collection.deleteOne({ _id: new ObjectId(id) })
    response.status(200).json(results)
})

// -------------- PRODUCTS ------------------

// GET
app.get('/api/products', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(PRODUCTS);

    const results = await collection.find({}).toArray()

    response.status(200).json(results)
})

// POST 
app.post('/api/products', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(PRODUCTS);

    const { nombre, precio } = request.body
    const results = await collection.insertOne({ nombre, precio });

    return response.status(200).json(results)
})

// GET 
app.get('/api/products/:id', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(PRODUCTS);

    const { id } = request.params
    const results = await collection.find({ _id: new ObjectId(id) }).toArray()

    response.status(200).json(results)
})

// PUT
app.put('/api/products/:id', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(PRODUCTS);

    const { id } = request.params
    const { nombre, precio } = request.body
    const results = await collection.updateOne({ _id: new ObjectId(id) }, { $set: { nombre, precio } });

    response.status(200).json(results)
})

// DELETE
app.delete('/api/products/:id', verifyToken, async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(PRODUCTS);

    const { id } = request.params
    const results = await collection.deleteOne({ _id: new ObjectId(id) })
    response.status(200).json(results)
})

app.use((err, request, response, next) => {
    console.error(err)
    if (err.name === 'BSONError')
        return response.status(400).json({ message: "ID no válido" })
    response.status(500).json({ message: "Error interno del servidor" })
})

try {
    await client.connect()
    console.log("Conectado a MongoDB")
} catch (err) {
    console.error("Error al conectar con MongoDB:", err.message)
}

app.listen(PORT, () => console.log(`Servidor web iniciado en puerto: ${PORT}`))

export default app
