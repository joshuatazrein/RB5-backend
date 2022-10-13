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
const { Client: Notion, collectPaginatedAPI } = require('@notionhq/client')

const {
  google: {
    auth: { OAuth2 }
  }
} = require('googleapis')

const express = require('express')
const cors = require('cors')
const app = express()
const port = process.env.PORT || 3001

const { getUser } = require('@notionhq/client/build/src/api-endpoints')

const crypto = require('crypto')
const { oauth2 } = require('googleapis/build/src/apis/oauth2')
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
app.use('/auth/notion/getDatabases', express.json())
app.use('/auth/ynab/setTransaction', express.json())
app.use('/auth/ynab/setTransactions', express.json())

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

const message = message => {
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

app.post('/auth/google/requestWithId', async (req, res) => {
  try {
    let user_email
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
    console.log('failed:', err.message)
    if (err.message === 'NO_USER') res.status(403).send(err.message)
    else {
      res.status(400).send(err.message)
    }
  }
})

app.post('/auth/notion/getDatabases', async (req, res) => {
  try {
    const { databaseKey, databaseIds } = req.body
    const notion = new Notion({
      auth: databaseKey
    })
    const databases = []
    for (let database_id of databaseIds) {
      const rawDatabase = await notion.databases.retrieve({
        database_id
      })

      const rawContent = await collectPaginatedAPI(notion.databases.query, {
        database_id
      })

      databases.push({ rawDatabase, rawContent })
    }
    res.send(databases)
  } catch (err) {
    res.status(400).send(err.message)
  }
})

app.get('/auth/ynab/getBudget', async (req, res) => {
  try {
    const access_token = req.query.access_token
    const budgetInfo = (
      await axios.request({
        url: 'https://api.youneedabudget.com/v1/budgets',
        headers: {
          Authorization: `bearer ${access_token}`
        }
      })
    ).data.data.budgets.sort((budgetA, budgetB) =>
      budgetA.last_modified_on > budgetB.last_modified_on ? -1 : 1
    )[0]

    const budget = (
      await axios.request({
        url: `https://api.youneedabudget.com/v1/budgets/${budgetInfo.id}`,
        headers: {
          Authorization: `bearer ${access_token}`
        }
      })
    ).data.data.budget

    const transactions = (
      await axios.request({
        url: `https://api.youneedabudget.com/v1/budgets/${budgetInfo.id}/transactions`,
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
        !['Hidden Categories', 'Internal Master Category'].includes(group.name)
    )

    res.send(budget)
  } catch (err) {
    console.log(err.message)
    res.status(400).send(err.message)
  }
})

app.post('/auth/ynab/setTransaction', async (req, res) => {
  try {
    const access_token = req.query.access_token
    const transaction = req.body
    const response = await axios.request({
      method: 'PUT',
      url: `https://api.youneedabudget.com/v1/budgets/${req.query.budget_id}/transactions/${transaction.id}`,
      headers: { Authorization: `bearer ${access_token}` },
      data: { transaction: transaction }
    })
    console.log(response.headers, response.data)
    res.send('success')
  } catch (err) {
    console.log(err.message)
    res.status(400).send(err.message)
  }
})

app.post('/auth/ynab/setTransactions', async (req, res) => {
  try {
    const access_token = req.query.access_token
    const transactions = req.body
    const response = await axios.request({
      method: 'PATCH',
      url: `https://api.youneedabudget.com/v1/budgets/${req.query.budget_id}/transactions`,
      headers: { Authorization: `bearer ${access_token}` },
      data: { transactions: transactions }
    })
    console.log(response.data)
    res.send('success')
  } catch (err) {
    console.log(err.message)
    res.status(400).send(err.message)
  }
})

app.listen(port, () => {})
