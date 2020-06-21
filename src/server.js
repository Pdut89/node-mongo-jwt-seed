require('dotenv').config()
require('./db/mongoose.js')

const { 
  PORT,
  CORS_ORIGIN_URL
} = process.env 

const corsConfig = {
  origin: CORS_ORIGIN_URL,
  optionsSuccessStatus: 200
}

const express = require('express')
const helmet = require('helmet')
const morgan = require('morgan')
const cors = require('cors')
const app = express()

const userRouter = require('./routers/user')
const authRouter = require('./routers/auth')

app.use(cors(corsConfig))
app.use(helmet())
app.use(morgan('common'))

app.use(express.json())
app.use(authRouter)
app.use(userRouter)

app.get('/', (req, res) => {
  res.send('Node Express Mongo Server')
})

app.listen(PORT, () => {
  console.log(`App is running on PORT:${PORT}`)
})

