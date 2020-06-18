const express = require('express')
const router = new express.Router()
const User = require('../models/user')

const { 
  auth,
  authSuperAdmin
} = require('../middleware/auth')

router.post('/user', async (req, res) => {
  const response = new User(req.body)

  try {
    await response.save()
    const user = response.getPublicProfile()
    const authTokens = await response.generateAuthTokens()
    
    res.status(201).send({ 
      user, 
      ...authTokens
    })
    
  } catch (error) {
    console.log(error)
    res.status(400).send(error)
  }
})

router.post('/user/login', async (req, res) => {
  const { email, password } = req.body
  try {
    const response = await User.findByCredentials(email, password)
    const user = response.getPublicProfile()
    const authTokens = await response.generateAuthTokens()

    res.send({ 
      user,
      ...authTokens
    })
  } catch (error) {
    console.log(error)
    res.status(400).send()
  }
})

router.post('/user/logout', auth, async (req,res) => {
  const { tokens } = req.user
  try {
    req.user.tokens = tokens.filter(({ accessToken }) => accessToken !== req.accessToken)
    await req.user.save()
    res.send()
  } catch (error) {
    console.log(error)
    res.status(500).send()
  }
})

router.get('/user', auth, async (req, res) => {
  try {
    const users = await User.find()
    const profiles = users.map(user => user.getPublicProfile())
    res.send(profiles)
  } catch (error) {
    console.error(error)
    res.status(500).send(error)
  }
})

router.get('/user/:id', auth, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
    if (!user) return res.status(404).send({ Error: 'User not found'})
    res.send({
      user: user.getPublicProfile()
    })
  } catch (error) {
    console.error(error)
    res.status(500).send(error)
  }
})

router.patch('/user/:id', auth, async (req, res) => {
  const updatedFields = Object.keys(req.body)
  const allowedFields = ['name', 'email', 'password', 'role']
  const isValidOperation = updatedFields.every(field => allowedFields.includes(field))

  if (!isValidOperation) return res.status(400).send({ error: 'Attempting to update invalid fields.'})

  try {
    const user = await User.findById(req.params.id) 
    updatedFields.forEach(field => user[field] = req.body[field])
    await user.save()

    if (!user) return res.status(404).send({ error: 'User not found'})
    res.send(user)
  } catch (error) {
    console.log(error)
    res.status(400).send(error)
  }
})

router.delete('/user/:id', authSuperAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id)
    if (!user) res.status(404).send({ error: 'User not found' })
    res.sendStatus(200)
  } catch (error) {
    console.log(error)
    res.status(500).send(error)
  }
})



module.exports = router