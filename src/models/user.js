require('dotenv').config()

const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const roles = require('../config/roles')

const { JWT_SECRET } = process.env

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    lowercase: true,
    unique: true,
    validate(val) {
      if (!validator.isEmail(val)) throw new Error('Invalid email')
    }
  },
  password: {
    type: String,
    required: true
  },
  tokens: [{
    token: {
      type: String,
      required: true
    }
  }],
  role: {
    type: String,
    required: true,
    validate(val) {
      console.log(roles)
      if (!roles.includes(val)) throw new Error('Not a valid role.')
    }
  }
}, {
  timestamps: true
})

userSchema.methods.getPublicProfile = function () {
  const user = this
  const userObj = user.toObject()

  delete userObj.password
  delete userObj.tokens
  delete userObj.token

  return userObj
}

userSchema.methods.generateAuthToken = async function () {
  const user = this
  const _id = user._id.toString()
  const config = { expiresIn: 3 }
  const token = jwt.sign({ _id }, JWT_SECRET.toString(), config)

  user.tokens = [...user.tokens, { token }]
  await user.save()
  
  return token
}

userSchema.statics.findByCredentials = async (email, password) => {
  const user = await User.findOne({ email })
  if (!user) throw new Error('User not found.')

  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) throw new Error('Unable to log in')

  return user
}

userSchema.pre('save', async function (next) {
  const user = this 
  if (user.isModified('password')) {
    user.password = await bcrypt.hash(user.password, 8)
  }
  next()
})

const User = mongoose.model('User', userSchema)

module.exports = User