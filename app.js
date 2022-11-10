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
  Client: Notion,
  collectPaginatedAPI,
  iteratePaginatedAPI
} = require('@notionhq/client')
const { google } = require('googleapis')
const {
  google: {
    auth: { OAuth2 }
  }
} = require('googleapis')

const express = require('express')
const cors = require('cors')
const app = express()
const port = process.env.PORT || 3001

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

const gmail = google.gmail({
  version: 'v1',
  auth: oauth2Client
})

const saveUsers = () =>
  fs.writeFile('./users.json', JSON.stringify(users), () => {})

app.use('/auth/google/request', express.json())
app.use('/auth/google/requestWithId', express.json({ limit: '50mb' }))
app.use('/auth/google/actionWithId', express.json({ limit: '50mb' }))
app.use('/auth/google/registerId', express.json())
app.use('/auth/google/registerTokens', express.json())
app.use('/auth/notion/getDatabases', express.json())
app.use('/auth/notion/register', express.json())
app.use('/auth/notion/action', express.json())
app.use('/auth/moments/action', express.json())

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

// for browser-based registration (server holds codes)
app.get('/auth/access', async (req, res) => {
  oauth2Client.getToken(req.query.code).then(
    async ({ tokens }) => {
      const userInfo = await oauth2Client.getTokenInfo(tokens.access_token)

      const user_email = userInfo.email

      if (!users[user_email]) {
        const encryptedId = encrypt(user_email)
        users[user_email] = {
          tokens,
          encryptedId,
          sharedLists: [],
          moments: {}
        }
        saveUsers()
      }

      const user_id =
        users[user_email].encryptedId.encryptedData +
        ';' +
        users[user_email].encryptedId.iv

      if (!req.query.noRedirect) {
        res.redirect(
          `${ORIGIN}/?user_id=${user_id}&user_email=${user_email}&scope=${users[user_email].tokens.scope}`
        )
      } else {
        res.json({
          user_id,
          user_email: user_email,
          sharedLists: users[user_email].sharedLists,
          scope: users[user_email].tokens.scope
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
      users[user_email] = { tokens, encryptedId, sharedLists: [], moments: {} }
      saveUsers()
    }

    const user_id =
      users[user_email].encryptedId.encryptedData +
      ';' +
      users[user_email].encryptedId.iv

    res.json({
      user_id,
      user_email: user_email,
      sharedLists: users[user_email].sharedLists,
      scope: users[user_email].tokens.scope
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

const message = (message, request) => {
  console.log(message)
}

const makeRequest = async (user_email, request) => {
  if (!users[user_email]) throw new Error('NO_USER')
  oauth2Client.setCredentials(users[user_email].tokens)
  const initialCredentials = { ...oauth2Client.credentials }
  const result = await oauth2Client.request(request)
  if (
    oauth2Client.credentials.access_token !== initialCredentials.access_token
  ) {
    users[user_email].tokens = { ...oauth2Client.credentials }
    saveUsers()
  }
  return result
}

app.post('/auth/google/actionWithId', async (req, res) => {
  try {
    const user_email = getEmailFromQuery(req)
    oauth2Client.setCredentials(users[user_email].tokens)
    const initialCredentials = { ...oauth2Client.credentials }

    const options = req.body
    let action
    switch (req.query.type) {
      case 'email.messages.send':
        action = () => gmail.users.messages.send(options)
        break
      default:
        break
    }

    action().then(
      result => {
        res.send(result.data)
        if (
          oauth2Client.credentials.access_token !==
          initialCredentials.access_token
        ) {
          users[user_email].tokens = { ...oauth2Client.credentials }
          saveUsers()
        }
      },
      err => {
        res.status(400).send(err.message)
      }
    )
  } catch (err) {
    message(err.message, {
      body: req.body,
      query: req.query,
      user: users[user_email]
    })
    if (['invalid_grant', 'NO_USER'].includes(err.message)) {
      delete users[user_email]
      res.status(403).send('NO_USER')
      return
    } else {
      message(err.message)
      res.status(400).send(err.message)
    }
  }
})

app.post('/auth/google/requestWithId', async (req, res) => {
  let user_email
  try {
    const request = req.body

    if (
      (request.url && /\/[^@\/]+@\w+\.\w+:\w+\/*/.test(request.url)) ||
      (request.params &&
        request.params.tasklist &&
        request.params.tasklist.includes(':'))
    ) {
      let splitId
      if (request.url && /\/[^@\/]+@\w+\.\w+:\w+\/*/.test(request.url)) {
        // it's a shared list, so use a different credential (mutates request itself)
        splitId = request.url
          .match(/\/[^@\/]+@\w+\.\w+:\w+\/*/)[0]
          .slice(1, -1)
          .split(':')
        request.url = request.url.replace(splitId.join(':'), splitId[1])
      }
      if (
        request.params &&
        request.params.tasklist &&
        request.params.tasklist.includes(':')
      ) {
        splitId = request.params.tasklist.split(':')
        request.params.tasklist = splitId[1]
      }
      user_email = splitId[0]
    } else {
      user_email = getEmailFromQuery(req)
    }
    const result = await makeRequest(user_email, request)

    if (
      request.url === 'https://tasks.googleapis.com/tasks/v1/users/@me/lists'
    ) {
      // adds in shared tasklists from RiverBank when listing task lists
      const mySharedLists = [...users[user_email].sharedLists]
      for (let sharedListId of mySharedLists) {
        const sharedUserEmail = sharedListId.split(':')[0]
        const listId = sharedListId.split(':')[1]

        if (!users[sharedUserEmail]) {
          message('NO_USER, deleting list')
          users[user_email].sharedLists.splice(
            users[user_email].sharedLists.indexOf(sharedListId),
            1
          )
          continue
        }

        let sharedList
        const sharedRequest = {
          method: 'GET',
          url: `https://tasks.googleapis.com/tasks/v1/users/@me/lists/${listId}`
        }

        try {
          sharedList = (await makeRequest(sharedUserEmail, sharedRequest)).data
          sharedList.id = sharedListId
          result.data.items.push(sharedList)
        } catch (err) {
          message('failed: ' + err.message)
        }
      }
    }
    res.send(result.data)
  } catch (err) {
    message(err.message, {
      body: req.body,
      query: req.query,
      user: users[user_email]
    })
    if (['invalid_grant', 'NO_USER'].includes(err.message)) {
      delete users[user_email]
      res.status(403).send('NO_USER')
      return
    } else {
      message(err.message, req)
      res.status(400).send(err.message)
    }
  }
})

app.post('/auth/notion/action', async (req, res) => {
  try {
    const data = req.body
    const user_email = getEmailFromQuery(req)
    const tokens = users[user_email].notion_tokens
    const notion = new Notion({
      auth: tokens.access_token
    })
    let response
    switch (req.query.action) {
      case 'search':
        response = await notion.search(data)
        break
      case 'databases.retrieve':
        response = await notion.databases.retrieve(data)
        break
      case 'databases.query':
        response = await collectPaginatedAPI(notion.databases.query, data)
        break
      case 'pages.update':
        response = await notion.pages.update(data)
        break
      default:
        break
    }
    res.send(response)
  } catch (err) {
    message(err.message)
    res.status(400).json(err)
  }
})

app.get('/auth/notion/register', async (req, res) => {
  const user_email = getEmailFromQuery({ query: { user_id: req.query.state } })
  const basicHeader = Buffer.from(
    `${keys.notion.client_id}:${keys.notion.client_secret}`
  ).toString('base64')
  const token = await axios
    .request({
      method: 'POST',
      url: 'https://api.notion.com/v1/oauth/token',
      headers: {
        Authorization: `Basic ${basicHeader}`
      },
      data: {
        grant_type: 'authorization_code',
        code: req.query.code,
        redirect_uri: `${SERVER}/notion/register`
      }
    })
    .catch(err => message(err))
  users[user_email].notion_tokens = token.data
  saveUsers()
  res.redirect(
    `${ORIGIN}?databaseKey=${encodeURIComponent(token.data.workspace_name)}`
  )
})

app.get('/auth/ynab/register', async (req, res) => {
  try {
    const user_email = getEmailFromQuery({
      query: { user_id: decodeURIComponent(req.query.state) }
    })
    const token = await axios
      .request({
        method: 'POST',
        url: 'https://app.youneedabudget.com/oauth/token',
        params: {
          client_id: keys.ynab.client_id,
          client_secret: keys.ynab.client_secret,
          redirect_uri: `${SERVER}/ynab/register`,
          grant_type: 'authorization_code',
          code: req.query.code
        }
      })
      .catch(err => message(err))

    users[user_email].ynab_tokens = token.data
    saveUsers()
    res.redirect(`${ORIGIN}?budgetKey=true`)
  } catch (err) {
    message(err)
  }
})

app.post('/auth/ynab/action', async (req, res) => {
  try {
    const user_email = getEmailFromQuery(req)
    let tokens = users[user_email].ynab_tokens
    if (tokens.created_at + tokens.expires_in <= new Date().getTime()) {
      tokens = (
        await axios.request({
          method: 'POST',
          url: 'https://app.youneedabudget.com/oauth/token',
          params: {
            client_id: keys.ynab.client_id,
            client_secret: keys.ynab.client_secret,
            grant_type: 'refresh_token',
            refresh_token: tokens.refresh_token
          }
        })
      ).data
      users[user_email].ynab_tokens = tokens
      saveUsers()
    }
    const { access_token } = tokens
    switch (req.query.action) {
      case 'getBudgets':
        const budget = (
          await axios.request({
            url: `https://api.youneedabudget.com/v1/budgets/default`,
            headers: {
              Authorization: `bearer ${access_token}`
            }
          })
        ).data.data.budget

        const transactions = (
          await axios.request({
            url: `https://api.youneedabudget.com/v1/budgets/default/transactions`,
            params: {
              type: 'unapproved'
            },
            headers: {
              Authorization: `bearer ${access_token}`
            }
          })
        ).data.data.transactions

        budget.transactions = transactions
        budget.categories = budget.categories.filter(
          category => !category.hidden && !category.deleted
        )
        budget.category_groups = budget.category_groups.filter(
          group =>
            !group.hidden &&
            !group.deleted &&
            !['Hidden Categories', 'Internal Master Category'].includes(
              group.name
            )
        )

        res.send(budget)
        break
      case 'setTransaction':
        const transaction = req.body
        response = await axios.request({
          method: 'PUT',
          url: `https://api.youneedabudget.com/v1/budgets/default/transactions/${transaction.id}`,
          headers: { Authorization: `bearer ${access_token}` },
          data: { transaction: transaction }
        })
        res.send('success')
        break
      case 'setTransactions':
        const multTransactions = req.body
        response = await axios.request({
          method: 'PATCH',
          url: `https://api.youneedabudget.com/v1/budgets/default/transactions`,
          headers: { Authorization: `bearer ${access_token}` },
          data: { transactions: multTransactions }
        })
        res.send('success')
        break
      default:
        break
    }
  } catch (err) {
    message(err)
    res.status(400).send(err.message)
  }
})

app.post('/auth/moments/action', async (req, res) => {
  try {
    const user_email = getEmailFromQuery(req)
    const momentID = req.query.mode + '::' + req.query.id
    switch (req.query.action) {
      case 'delete':
        delete users[user_email].moments[momentID]
        break
      case 'set':
        users[user_email].moments[momentID] = req.body
        break
      case 'load':
        res.json(users[user_email].moments)
        return
      default:
        break
    }
    saveUsers()
    res.send('success')
  } catch (err) {
    message(err.message)
    res.status(400).send(err.message)
  }
})

app.listen(port, () => {})
