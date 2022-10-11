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

const { getUser } = require('@notionhq/client/build/src/api-endpoints')

const crypto = require('crypto')
const key = Buffer.from(keys.cipher.key)

function encrypt(text) {
  const iv = crypto.randomBytes(16)
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  let encrypted = cipher.update(text)
  encrypted = Buffer.concat([encrypted, cipher.final()])
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted.toString('hex')
  }
}

function decrypt(text) {
  const iv = Buffer.from(text.iv, 'hex')
  let encryptedText = Buffer.from(text.encryptedData, 'hex')

  let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv)
  let decrypted = decipher.update(encryptedText)
  decrypted = Buffer.concat([decrypted, decipher.final()])

  return decrypted.toString()
}

function getEmailFromQuery(req) {
  const encryptedId = req.query.user_id.split(';')
  const encryptedData = encryptedId[0]
  const iv = encryptedId[1]
  const user_email = decrypt({ encryptedData, iv })
  return user_email
}

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

      const user_email = userInfo.email

      if (!users[user_email]) {
        const encryptedId = encrypt(user_email)
        users[user_email] = { tokens, encryptedId, sharedLists: [] }
        saveUsers()
      }

      const user_id =
        users[user_email].encryptedId.encryptedData +
        ';' +
        users[user_email].encryptedId.iv

      if (!req.query.noRedirect) {
        res.redirect(`${ORIGIN}/?user_id=${user_id}&user_email=${user_email}`)
      } else {
        res.json({
          user_id,
          user_email: user_email,
          sharedLists: users[user_email].sharedLists
        })
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
    const user_email = userInfo.email
    if (!users[user_email]) {
      const encryptedId = encrypt(user_email)
      users[user_email] = { tokens, encryptedId, sharedLists: [] }
      saveUsers()
    }

    const user_id =
      users[user_email].encryptedId.encryptedData +
      ';' +
      users[user_email].encryptedId.iv

    res.json({
      user_id,
      user_email: user_email,
      sharedLists: users[user_email].sharedLists
    })
  } catch (err) {
    res.status(400).send(err.message)
  }
})

app.get('/auth/google/addSharedList', async (req, res) => {
  try {
    const { list_id } = req.query
    const user_email = getEmailFromQuery(req)
    if (!users[user_email]) {
      res.status(401).send('NO_USER')
      return
    }
    if (!users[user_email].sharedLists.includes(list_id)) {
      users[user_email].sharedLists.push(list_id)
      saveUsers()
    }
    res.json(users[user_email].sharedLists)
  } catch (err) {
    console.log(err)
    res.status(400).send(err.message)
  }
})

app.get('/auth/google/removeSharedList', async (req, res) => {
  try {
    const { list_id } = req.query
    const user_email = getEmailFromQuery(req)
    if (!users[user_email]) {
      res.status(401).send('NO_USER')
      return
    }
    if (users[user_email].sharedLists.includes(list_id)) {
      users[user_email].sharedLists.splice(
        users[user_email].sharedLists.indexOf(list_id),
        1
      )
      saveUsers()
    }
    res.json(users[user_email].sharedLists)
  } catch (err) {
    console.log(err)
    res.status(400).send(err.message)
  }
})

app.get('/auth/google/signOut', async (req, res) => {
  try {
    const user_email = getEmailFromQuery(req)
    const token = users[user_email].tokens.access_token
    delete users[user_email]
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

const message = message => {
  console.log(message)
}

app.post('/auth/google/requestWithId', async (req, res) => {
  let user_email
  const request = req.body
  try {
    if (request.url && /\/[^@\/]+@\w+\.\w+:\w+\//.test(request.url)) {
      // it's a shared list, so use a different credential (mutates request itself)
      const listId = request.url
        .match(/\/[^@\/]+@\w+\.\w+:\w+\//)[0]
        .slice(1, -1)
      request.url = request.url.replace(listId, listId.split(':')[1])
      user_email = listId.split(':')[0]
      console.log('RECEIVED SHARED REQUEST:', listId, request)
    } else if (
      request.params &&
      request.params.tasklist &&
      request.params.tasklist.includes(':')
    ) {
      // tasklist in params, use different credential
      const listId = request.params.tasklist
      request.params.tasklist = listId.split(':')[1]
      user_email = listId.split(':')[0]
      console.log('RECEIVED SHARED REQUEST:', listId, request)
    } else {
      user_email = getEmailFromQuery(req)
    }
  } catch (err) {
    message(err.message)
    res.status(400).send(err.message)
    return
  }

  try {
    if (!users[user_email]) {
      res.status(401).send('NO_USER')
      return
    }

    request.headers = {
      ...request.headers,
      Authorization: `Bearer ${users[user_email].tokens.access_token}`
    }
    const result = await axios.request(request)

    if (
      request.url === 'https://tasks.googleapis.com/tasks/v1/users/@me/lists'
    ) {
      // adds in shared tasklists from RiverBank when listing task lists
      console.log('getting shared lists')
      const mySharedLists = [...users[user_email].sharedLists]
      for (let sharedListId of mySharedLists) {
        const sharedUserEmail = sharedListId.split(':')[0]
        const listId = sharedListId.split(':')[1]

        const sharedRequest = {
          method: 'GET',
          url: `https://tasks.googleapis.com/tasks/v1/users/@me/lists/${listId}`,
          headers: {
            Authorization: `Bearer ${users[sharedUserEmail].tokens.access_token}`
          }
        }
        try {
          let sharedList
          try {
            sharedList = (await axios.request(sharedRequest)).data
            sharedList.id = sharedListId
            result.data.items.push(sharedList)
          } catch (err) {
            if (err.response && [401, 403].includes(err.response.status)) {
              console.log('expired access token, refreshing')
              oauth2Client.setCredentials(users[sharedUserEmail].tokens)
              const { credentials: tokens } =
                await oauth2Client.refreshAccessToken()
              console.log('refreshed tokens')
              if (!tokens) throw new Error("tokens didn't work")
              users[sharedUserEmail] = {
                ...users[sharedUserEmail],
                tokens
              }
              saveUsers()
              sharedRequest.headers = {
                ...sharedRequest.headers,
                Authorization: `Bearer ${users[sharedUserEmail].tokens.access_token}`
              }
              sharedList = await axios.request(sharedRequest)
              sharedList.id = sharedListId
              result.data.items.push(sharedList)
            }
          }
        } catch (err) {
          message('shared lists failed', err.message)
          users[user_email].sharedLists.splice(
            users[user_email].sharedLists.indexOf(sharedListId),
            1
          )
        }
      }
    }

    res.send(result.data)
  } catch (err) {
    message(err.message + '\nData recieved: ' + JSON.stringify(req.body))
    if (err.response && [401, 403].includes(err.response.status)) {
      try {
        oauth2Client.setCredentials(users[user_email].tokens)
        const { credentials: tokens } = await oauth2Client.refreshAccessToken()
        console.log(tokens)
        if (!tokens) throw new Error("tokens didn't work")
        users[user_email] = {
          ...users[user_email],
          tokens
        }
        saveUsers()

        request.headers = {
          ...request.headers,
          Authorization: `Bearer ${users[user_email].tokens.access_token}`
        }
        const result = await axios.request(request)

        res.send(result.data)
      } catch (err) {
        message(err.message)
        if (err.message === 'invalid_grant') {
          delete users[user_email]
          res.status(401).send('NO_USER')
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
