const process = require('process')
const ORIGIN = process.env.PATH.includes('/Users/jreinier')
  ? 'http://localhost:3000'
  : 'https://riverbank.app'
const SERVER = process.env.PATH.includes('/Users/jreinier')
  ? 'http://localhost:3001/auth'
  : 'https://riverbank.app/auth'
const keys = require('./keys.json')
const axios = require('axios')
const users = require('./users.json')
const fs = require('fs')

const {
  google: {
    auth: { OAuth2 }
  }
} = require('googleapis')

const express = require('express')
const cors = require('cors')
const { signInMyNotion } = require('./notionApi')
const app = express()
const port = process.env.PORT || 3001

const oauth2Client = new OAuth2(
  keys.web.client_id,
  keys.web.client_secret,
  `${SERVER}/access`
)

app.use('/auth/google/request', express.json())
app.use('/auth/google/requestWithId', express.json())
var allowedDomains = ['capacitor://localhost', 'http://localhost:3000']
app.use(
  cors({
    origin: function (origin, callback) {
      // bypass the requests with no origin (like curl requests, mobile apps, etc )
      if (!origin) return callback(null, true)

      if (allowedDomains.indexOf(origin) === -1) {
        var msg = `This site ${origin} does not have an access. Only specific domains are allowed to access it.`
        return callback(new Error(msg), false)
      }
      return callback(null, true)
    }
  })
)

// for browser-based registration (server holds codes)
app.get('/auth/access', async (req, res) => {
  oauth2Client.getToken(req.query.code).then(
    async ({ tokens }) => {
      const userInfo = await oauth2Client.getTokenInfo(tokens.access_token)
      console.log(userInfo)
      const user_id = userInfo.email
      users[user_id] = tokens
      console.log(users)
      fs.writeFile('./users.json', JSON.stringify(users), () =>
        console.log('wrote file')
      )
      res.redirect(`${ORIGIN}/?user_id=${user_id}`)
    },
    err => {
      res.redirect(`${ORIGIN}/?err=${err.message}`)
    }
  )
})

app.get('/auth/revoke', async (req, res) => {
  oauth2Client.revokeToken(req.query.access_token).then(
    () => res.send('success'),
    err => res.send(err.message)
  )
})

app.get('/auth/refresh', async (req, res) => {
  try {
    const refresh_token = users[req.query.userEmail]
    oauth2Client.setCredentials({
      refresh_token
    })
    const newToken = await oauth2Client.refreshAccessToken()
    res.json(newToken.credentials)
  } catch (err) {
    res.send(err.message)
  }
})

app.get('/auth/notion/signIn', async (req, res) => {
  try {
    res.json(await signInMyNotion())
  } catch (err) {
    res.status(400).send(err.message)
  }
})

app.post('/auth/google/request', async (req, res) => {
  try {
    console.log(req, req.body)
    const result = await axios.request(req.body)
    res.send(result.data)
  } catch (err) {
    console.log(err)
    res
      .status(400)
      .send(err.message + '\nData recieved: ' + JSON.stringify(req.body))
  }
})

app.post('/auth/google/requestWithId', async (req, res) => {
  try {
    console.log(req, req.body)
    const request = req.body
    request.headers = {
      ...request.headers,
      Authorization: `Bearer ${users[req.query.user_id].access_token}`
    }
    console.log(request)
    const result = await axios.request(request)
    res.send(result.data)
  } catch (err) {
    console.log(err)
    res
      .status(400)
      .send(err.message + '\nData recieved: ' + JSON.stringify(req.body))
  }
})

app.listen(port, () => {})
