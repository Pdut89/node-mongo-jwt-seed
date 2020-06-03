require('dotenv').config()

const express = require('express')
const mongoose = require('mongoose')
const app = express()

const { 
  PORT, 
  MONGO_URL, 
  DB_NAME 
} = process.env

mongoose.connect(`${MONGO_URL}/${DB_NAME}`, {
  useNewUrlParser: true,
  useCreateIndex: true
}) 
 
const User = mongoose.model('Stealing', {
  name: {
    type: String,
  },
  age: {
    type: Number
  }
})

const me = new User({
  name: 'Pieter',
  age: 30
})

me.save().then(() => {
  console.log(me)
}).catch(err => {
  console.log(err)
})

app.get('/', function (req, res) {
  res.send('Remax MongoDB Server')
})

app.listen(PORT, () => {
  console.log(`App is running on PORT:${PORT}`)
})

