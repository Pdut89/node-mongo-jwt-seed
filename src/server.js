require('dotenv').config()
require('./db/mongoose.js')

const { PORT } = process.env

const express = require('express')
const app = express()

const userRouter = require('./routers/user')

app.use(express.json())
app.use(userRouter)

app.get('/', (req, res) => {
  res.send('Remax MongoDB Server')
})

app.listen(PORT, () => {
  console.log(`App is running on PORT:${PORT}`)
})

