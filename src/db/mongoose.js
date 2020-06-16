
const mongoose = require('mongoose')

const {
  MONGO_URL,
  DB_NAME
} = process.env

async function connectToMongo() {
  try {
    await mongoose.connect(`${MONGO_URL}/${DB_NAME}`, {
      useNewUrlParser: true,
      useCreateIndex: true,
      useFindAndModify: false
    })
    console.log('Connected to mongo db.')
  } catch (err) {
    console.log('Failed to connect to mongo db: ', err)
  }
}

connectToMongo() 