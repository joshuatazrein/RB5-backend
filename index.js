const keys = require('./keys.json')

const {
  google: {
    auth: { OAuth2 }
  }
} = require('googleapis')

const express = require('express')
const cors = require('cors')
const app = express()
const port = 3001

const oauth2Client = new OAuth2(
  keys.web.client_id,
  keys.web.client_secret,
  'http://localhost:3001/access'
)

// generate a url that asks permissions for Blogger and Google Calendar scopes
const scopes = [
  'https://www.googleapis.com/auth/drive.appdata',
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/tasks',
  'https://www.googleapis.com/auth/calendar.readonly',
  'https://www.googleapis.com/auth/calendar.events'
]

const url = oauth2Client.generateAuthUrl({
  // 'online' (default) or 'offline' (gets refresh_token)
  access_type: 'offline',

  // If you only need one scope you can pass it as a string
  scope: scopes
})

console.log(url)

app.get('/access', async (req, res) => {
  console.log(req.query.code)
  // res.json({ code: req.query.code })
  const { tokens } = await oauth2Client.getToken(req.query.code)
  console.log(tokens)
  res.redirect(
    `http://localhost:3000/?access_token=${tokens.access_token}&scope=${tokens.scope}&expiry_date=${tokens.expiry_date}` +
      (tokens.refresh_token ? `&refresh_token=${tokens.refresh_token}` : '')
  )
})

app.get(
  '/revoke',
  cors({ origin: 'http://localhost:3000' }),
  async (req, res) => {
    oauth2Client.revokeToken(req.query.access_token)
    res.send('success')
  }
)

app.get(
  '/refresh',
  cors({ origin: 'http://localhost:3000' }),
  async (req, res) => {
    const refresh_token = req.query.refresh_token
    oauth2Client.setCredentials({
      refresh_token
    })
    console.log(oauth2Client.credentials, refresh_token)
    const newToken = await oauth2Client.refreshAccessToken()
    console.log(newToken, newToken.credentials)
    res.json(newToken.credentials)
  }
)

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
