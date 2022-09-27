const process = require('process')
const ORIGIN = process.env.PATH.includes('/Users/jreinier')
  ? 'http://localhost:3000'
  : 'https://riverbank.app'
const SERVER = process.env.PATH.includes('/Users/jreinier')
  ? 'http://localhost:3001/auth'
  : 'https://riverbank.app/auth'
const keys = require('./keys.json')
const axios = require('axios')

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
app.use(cors({ origin: 'http://localhost:3000' }))

app.get('/auth/access', async (req, res) => {
  oauth2Client.getToken(req.query.code).then(
    ({ tokens }) => {
      res.redirect(
        `${ORIGIN}/?access_token=${tokens.access_token}&scope=${tokens.scope}&expiry_date=${tokens.expiry_date}` +
          (tokens.refresh_token ? `&refresh_token=${tokens.refresh_token}` : '')
      )
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
    const refresh_token = req.query.refresh_token
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
    const result = await axios.request(req.body)
    res.send(result.data)
  } catch (err) {
    console.log(err)
    res.status(400).send(err.message)
  }
})

app.listen(port, () => {})
