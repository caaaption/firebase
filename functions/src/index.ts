import * as functions from 'firebase-functions'
import * as admin from 'firebase-admin'
import * as express from 'express'
import * as cors from 'cors'
import { SiweMessage, generateNonce } from 'siwe'

const app: express.Express = express()
app.use(cors({ origin: true }))

admin.initializeApp()

app.post('/nonce', async (req, res) => {
  res.set({ 'Access-Control-Allow-Origin': '*' })
  const { address } = req.body
  if (!address) return res.status(422).json({ message: 'Invalid address' })
  
  const user = await admin.firestore().doc(`/nonces/${address}`).get()
  if (user.exists) {
    return res.send({
      nonce: user.data()?.nonce,
    })
  }

  const nonce = generateNonce()

  await admin.firestore().doc(`/nonces/${address}`).set({
    nonce: nonce,
  })

  return res.status(200).json({
    nonce: nonce,
  })
})

app.post('/verify', async (req, res) => {
  res.set({ 'Access-Control-Allow-Origin': '*' })
  try {
    const { address, message, signature } = req.body
    if (!address) return res.status(422).json({ message: 'Invalid address' })
    if (!message) return res.status(422).json({ message: 'Invalid message' })
    if (!signature) return res.status(422).json({ message: 'Invalid signature' })
  
    const siweMessage = new SiweMessage(message)
    const fields = await siweMessage.validate(signature)
  
    const userReference = admin.firestore().doc(`/nonces/${address}`)
    const user = await userReference.get()
    const nonce = user.data()?.nonce
  
    if (fields.nonce !== nonce) {
      return res.status(422).json({
        message: 'Invalid nonce',
      })
    }
  
    await userReference.set({
      nonce: generateNonce(),
    })
  
    admin.auth().getUser(address)
      .catch((error) => {
        admin.auth().createUser({
          uid: address,
        })
      })
  
    const customToken = await admin.auth().createCustomToken(address)
    return res.status(200).json({
      token: customToken,
    })
  } catch (error) {
    console.error(error)
    return res.json({
      error: error,
    })
  }
})

exports.api = functions.region('asia-northeast1').https.onRequest(app)