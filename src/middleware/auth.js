require('dotenv').config()
const roles = require('../config/roles')
const jwt = require('jsonwebtoken')
const User = require('../models/user')

const { ACCESS_TOKEN_SECRET } = process.env

function throwPermissionsError (res) {
  res.status(403).send({ error: 'User does not have the required permissions'})
}

const authenticate = async (req, res) => {
  try {
    const accessToken = req.header('Authorization').replace('Bearer ', '')
    const decoded = jwt.verify(accessToken, ACCESS_TOKEN_SECRET)

    const user = await User.findOne({
      _id: decoded._id,
      'tokens.accessToken': accessToken
    })

    if (!user) throw new Error('Could not find user with matching access token')

    req.accessToken = accessToken
    req.user = user

    return user.role

  } catch (error) {
    console.log(error)
    res.status(401).send({ error: 'Please authenticate.' })
  } 
}

const auth = async (req, res, next) => {
  const role = await authenticate(req, res)
  if (role) next()
}

const authAdmin = async (req, res, next) => {
  const { superAdmin, admin } = roles
  const role = await authenticate(req, res)
  const isAdmin = [superAdmin, admin].includes(role)
  if (!isAdmin) return throwPermissionsError(res) 
  next()
}

const authSuperAdmin = async (req, res, next) => {
  const role = await authenticate(req, res)
  const isSuperAdmin = role === roles.superAdmin
  if (!isSuperAdmin) return throwPermissionsError(res) 
  next()
}

module.exports = {
  authSuperAdmin,
  authAdmin,
  auth
}