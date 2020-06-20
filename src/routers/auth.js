const express = require('express')
const router = new express.Router()
const User = require('../models/user')

const { auth } = require('../middleware/auth')

router.post('/auth', async (req, res) => {
  const { email, password } = req.body
  try {
    const response = await User.findByCredentials(email, password)
    const user = response.getPublicProfile()
    const authTokens = await response.generateAuthTokens()
    await User.removeInvalidTokens(email)

    res.send({
      user,
      ...authTokens
    })
  } catch (error) {
    console.log(error)
    res.status(400).send(error.message)
  }
})

router.post('/auth/verify', auth, async (req, res) => {
  res.status(200).send({
    shouldRefreshToken: req.shouldRefreshToken
  })
})

router.post('/auth/refresh', async (req, res) => {
  const accessToken = req.header('Authorization').replace('Bearer ', '')
  const { email, refreshToken } = req.body
  try {
    const response = await User.verifyRefreshToken(email, refreshToken, accessToken)
    const user = response.getPublicProfile()
    const authTokens = await response.generateAuthTokens()

    res.send({
      user,
      ...authTokens
    })
  } catch (error) {
    console.log(error)
    res.status(401).send(error)
  } finally {
    User.removeInvalidTokens(null, null, refreshToken)
  }
})

router.post('/auth/logout', async (req, res) => {
  const accessToken = req.header('Authorization').replace('Bearer ', '')
  try {
    await User.removeInvalidTokens(null, accessToken)
    res.send('User logged out successfully')
  } catch (error) {
    console.log(error)
    res.status(500).send(error)
  }
})

module.exports = router