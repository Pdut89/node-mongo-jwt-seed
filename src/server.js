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
const cors = require('cors')
const app = express()

const userRouter = require('./routers/user')

app.use(cors(corsConfig))
app.use(express.json())
app.use(userRouter)

app.get('/', (req, res) => {
  res.send('Remax MongoDB Server')
})

app.listen(PORT, () => {
  console.log(`App is running on PORT:${PORT}`)
})

