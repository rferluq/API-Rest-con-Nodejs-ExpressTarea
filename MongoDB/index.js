import { MongoClient, ObjectId } from 'mongodb' // Documentación CRUD: https://mongodb.github.io/node-mongodb-native/6.2/
import express from "express";
import "express-async-errors"
import cors from "cors";
import rateLimit from "express-rate-limit"
import bcrypt from "bcryptjs"  // Hashing de contraseñas
import jwt from "jsonwebtoken" // Generacion y verificacion de tokens
import swaggerUi from "swagger-ui-express"
import swaggerDocument from "./openapi.json" with { type: "json" }
// Para que swagger funcione correctamente en Vercel es necesario archivo vercel.json
// y añadir configuración indicada en https://github.com/swagger-api/swagger-ui/issues/9924#issuecomment-3360835086


const SECRET_KEY = process.env.JWT_SECRET // Secreto para firmar y verificar el token
const REFRESH_KEY = process.env.JWT_REFRESH_SECRET
const app = express()

const PORT = process.env.PORT ?? 3000
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const DB_NAME = process.env.DB_NAME ?? 'api'
const VEHICLES = 'vehiculos'

const client = new MongoClient(DB_URL)





app.use(express.json())   // IMPORTANTE
app.use(cors())           // Para habilitar CORS

app.set('trust proxy', 1)

const limitMessage = { message: "Demasiadas peticiones, inténtalo más tarde" }
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, message: limitMessage }))
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, message: limitMessage })


app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument)
)



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


// Redirigir a la documentación de la API
app.get("/", (request, response) => response.redirect("/api-docs"))


// LOGIN
app.post('/api/login', authLimiter, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const { nombre, password } = request.body

    const user = Users.find(u => u.nombre == nombre)

    if (user == undefined) {
        return response.json({ message: "Usuario no encontrado" })
    }

    // Comparamos la contraseña
    const correctPassword = await bcrypt.compare(password, user.password)

    if (!correctPassword) {
        return response.json({ message: "Contraseña incorrecta" })
    }

    // Generamos el token firmado con secreto
    const token = jwt.sign(
        { id: user.id, nombre: user.nombre },
        SECRET_KEY,
        { expiresIn: '5m' }
    )

    const refreshToken = jwt.sign(
        { id: user.id, nombre: user.nombre },
        REFRESH_KEY,
        { expiresIn: '7d' }
    )

    response.json({ token, refreshToken })
})


// REFRESH
app.post('/api/refresh', authLimiter, (request, response) => {
    const { refreshToken } = request.body ?? {}

    if (!refreshToken)
        return response.status(400).json({ message: "Refresh token requerido" })

    try {
        const { id, nombre } = jwt.verify(refreshToken, REFRESH_KEY)
        const token = jwt.sign({ id, nombre }, SECRET_KEY, { expiresIn: '5m' })
        response.json({ token })
    } catch (err) {
        response.status(403).json({ message: "Refresh token inválido o expirado" })
    }
})


// -------------- VEHICLES ------------------

// GET
app.get('/api/vehiculos', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(VEHICLES);

    const results = await collection.find({}).toArray()

    response.status(200).json(results)
})

// POST 
app.post('/api/vehiculos', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(VEHICLES);

    const { marca, modelo, anio } = request.body
    const results = await collection.insertOne({ marca, modelo, anio });

    return response.status(200).json(results)
})

// GET 
app.get('/api/vehiculos/:id', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(VEHICLES);

    const { id } = request.params
    const results = await collection.find({ _id: new ObjectId(id) }).toArray()

    response.status(200).json(results)
})

// PUT
app.put('/api/vehiculos/:id', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(VEHICLES);

    const { id } = request.params
    const { marca, modelo, anio } = request.body
    const results = await collection.updateOne({ _id: new ObjectId(id) }, { $set: { marca, modelo, anio } });

    response.status(200).json(results)
})

// DELETE
app.delete('/api/vehiculos/:id', verifyToken, async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(VEHICLES);

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
