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

const saveUsers = () =>
  fs.writeFile('./users.json', JSON.stringify(users), () => {})

app.use('/auth/google/request', express.json())
app.use('/auth/google/requestWithId', express.json({ limit: '50mb' }))
app.use('/auth/google/registerId', express.json())
app.use('/auth/google/registerTokens', express.json())

var allowedDomains = [
  'capacitor://localhost',
  'http://localhost:3000',
  'https://riverbank.app'
]
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

app.get('/auth/notion/signIn', async (req, res) => {
  try {
    res.json(await signInMyNotion())
  } catch (err) {
    res.status(400).send(err.message)
  }
})

// for browser-based registration (server holds codes)
app.get('/auth/access', async (req, res) => {
  oauth2Client.getToken(req.query.code).then(
    async ({ tokens }) => {
      const userInfo = await oauth2Client.getTokenInfo(tokens.access_token)

      const user_id = userInfo.email

      users[user_id] = tokens
      saveUsers()

      if (!req.query.noRedirect) {
        res.redirect(`${ORIGIN}/?user_id=${user_id}`)
      } else {
        res.send(user_id)
      }
    },
    err => {
      if (!req.query.noRedirect) {
        res.redirect(`${ORIGIN}/?err=${err.message}`)
      } else {
        res.send(err.message + ' Recieved: ' + JSON.stringify(req.query))
      }
    }
  )
})

app.post('/auth/google/registerTokens', async (req, res) => {
  try {
    const tokens = req.body
    const userInfo = await oauth2Client.getTokenInfo(tokens.access_token)
    const user_id = userInfo.email
    users[user_id] = tokens
    saveUsers()
    res.send(user_id)
  } catch (err) {
    res.status(400).send(err.message)
  }
})

app.get('/auth/google/signOut', async (req, res) => {
  try {
    const token = users[req.query.user_id].access_token
    delete users[req.query.user_id]
    oauth2Client.revokeToken(token).then(
      () => {
        saveUsers()
        res.send('success')
      },
      err => res.status(400).send(err.message)
    )
  } catch (err) {
    res.status(400).send(err.message)
  }
})

app.post('/auth/google/requestWithId', async (req, res) => {
  try {
    const request = req.body
    request.headers = {
      ...request.headers,
      Authorization: `Bearer ${users[req.query.user_id].access_token}`
    }
    const result = await axios.request(request)

    res.send(result.data)
  } catch (err) {
    if (err.response && [401, 403].includes(err.response.status)) {
      try {
        // re-initialize client

        oauth2Client.setCredentials(users[req.query.user_id])
        const { credentials } = await oauth2Client.refreshAccessToken()
        users[req.query.user_id] = credentials
        saveUsers()

        const request = req.body
        request.headers = {
          ...request.headers,
          Authorization: `Bearer ${users[req.query.user_id].access_token}`
        }
        const result = await axios.request(request)

        res.send(result.data)
      } catch (err) {
        if (err.message === 'invalid_grant') {
          res.status(401).send(err.message)
        } else {
          res
            .status(400)
            .send(err.message + '\nData recieved: ' + JSON.stringify(req.body))
        }
      }
    } else {
      res
        .status(400)
        .send(err.message + '\nData recieved: ' + JSON.stringify(req.body))
    }
  }
})

app.listen(port, () => {})
