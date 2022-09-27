const { Client: Notion, collectPaginatedAPI } = require('@notionhq/client')
const { notion: notionKeys } = require('./keys.json')
let notion

async function signInMyNotion() {
  notion = new Notion({
    auth: notionKeys.secret
  })
  const databases = []
  for (let database_id of notionKeys.database_ids) {
    const database = await getDatabase(database_id)
    databases.push(database)
  }
  return databases
}

async function getDatabase(database_id) {
  const rawDatabase = await notion.databases.retrieve({
    database_id
  })

  const rawContent = await collectPaginatedAPI(notion.databases.query, {
    database_id: database_id
  })

  return { rawDatabase, rawContent }
}

module.exports = {
  getDatabase,
  signInMyNotion
}
