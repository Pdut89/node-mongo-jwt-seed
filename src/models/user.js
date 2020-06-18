require('dotenv').config()

const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const roles = require('../config/roles')

const { 
  ACCESS_TOKEN_SECRET, 
  REFRESH_TOKEN_SECRET,
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY
} = process.env

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
    accessToken: {
      type: String,
      required: true
    },
    refreshToken: {
      type: String,
      required: true
    }
  }],
  role: {
    type: String,
    required: true,
    validate(val) {
      const rolesArr = Object.keys(roles).map(key => roles[key])
      if (!rolesArr.includes(val)) throw new Error('Not a valid role.')
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
  delete userObj.accessToken

  return userObj
}

userSchema.methods.generateAuthTokens = async function () {
  const user = this
  const _id = user._id.toString()
  
  const config = isRefreshToken => ({ 
    expiresIn: parseInt(isRefreshToken ? REFRESH_TOKEN_EXPIRY : ACCESS_TOKEN_EXPIRY) 
  })

  const accessToken = jwt.sign({ _id }, ACCESS_TOKEN_SECRET.toString(), config())
  const refreshToken = jwt.sign({ _id }, REFRESH_TOKEN_SECRET.toString(), config(true))

  user.tokens = [...user.tokens, { accessToken, refreshToken }]
  await user.save()
  
  return {
    accessToken,
    refreshToken
  }
}

userSchema.statics.removeInvalidTokens = async (email, token) => {
  const user = await User.findOne({ email })
  if (!user) throw new Error('User not found')

  const { tokens } = user
  user.tokens = tokens
    .filter(({ accessToken }) => token ? accessToken !== token : true)
    .filter(({refreshToken}) => {
      const { exp } = jwt.decode(refreshToken)
      const isExpired = Date.now() >= exp * 1000
      return !isExpired
    })

  await user.save()
  return
}

userSchema.statics.findByCredentials = async (email, password) => {
  const user = await User.findOne({ email })
  if (!user) throw new Error('Invalid login details')

  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) throw new Error('Invalid login details')

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