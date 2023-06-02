const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config()
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');


const app = express()
const port = process.env.PORT || 5000

// middleware
app.use(cors())
app.use(express.json())



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.5j7d2x6.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// middleware jwt function it goes into the middle of jwt get api

  const verifyJWT = async(req,res,next) =>{
    const authorization = req.headers.authorization;
    if(!authorization){
      return res.status(401).send({error: true, message: 'unauthorized access'})
    }
    // bearer token  token is literally it means the token value you get from the user by authorization in headers
    const token = authorization.split(' ')[1];

    // token verify main function from jwt docs
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
      if(err){
        return res.status(401).send({error: true, message: 'unauthorized access'})
      }
      // if the jwt token is verified
      req.decoded = decoded;
      next() // passing to the next function
    })
  }

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    
    const usersCollection = client.db("BistroDb").collection("users");
    const menuCollection = client.db("BistroDb").collection("menu");
    const reviewCollection = client.db("BistroDb").collection("reviews");
    const cartCollection = client.db("BistroDb").collection("carts");

    // jwt api

    app.post('/jwt', (req, res) =>{
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '1h'
      })
      res.send({ token });
    })

    // user related api's

    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    })

    app.post('/users', async(req, res) => {
      const user = req.body
      // console.log(user)
      const query = { email: user.email }
      const existingUser = await usersCollection.findOne(query)
      // console.log("existing user",existingUser)
      if(existingUser){
        return res.send({ message: 'user already exists' })
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    })
    // api to check if the user is an admin or not
    // verify jwt is the first security layer
    app.get('/users/admin/:email',verifyJWT, async(req,res) => {
      const email = req.params.email;
      // adding second layer of security checking theemail address that is calling 
      // the api with the token is the same the email we get from decoding the token
      if(req.decoded.email !== email){
        return res.send({ admin : false })
      }
      const query = { email : email}
      const user = await usersCollection.findOne(query)
      const result = { admin: user?.role === 'admin' }
      res.send(result);
    })

    app.patch('/users/admin/:id', async(req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) }
      const updateDoc = {
        $set: {
          role : 'admin'
        },
      }
      const result = await usersCollection.updateOne(filter, updateDoc);
      res.send(result);
    })

    // menu related api's
    app.get('/menu', async(req,res)=>{
        const result = await menuCollection.find().toArray();
        res.send(result)
    })

    // review related api's
    app.get('/reviews', async(req,res)=>{
        const result = await reviewCollection.find().toArray();
        // const result = await reviewCollection.find().toArray();
        res.send(result)
    })

    // cart collection apis
    app.get('/carts', verifyJWT, async(req, res) => {
      const email = req.query?.email;
      if(!email){
        return res.send([]);
      }
      const decodedEmail = req.decoded.email // getting the decoded email from the response of jwt
      if(email !== decodedEmail){
        //adding extra level of security
        return res.status(403).send({error: true, message: 'forbidden access'})
      }
      const query = { email : email};
      const result = await cartCollection.find(query).toArray();
      res.send(result)
    })
    app.post('/carts', async(req,res) => {
      const item = req.body;
      // console.log(item)
      const result = await cartCollection.insertOne(item)
      res.send(result);
    })

    app.delete('/carts/:id', async(req,res) => {
      const id = req.params.id;
      console.log(id)
      const query = { _id : new ObjectId(id) }
      const result = await cartCollection.deleteOne(query)
      res.send(result);
    })

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);


app.get('/', (req,res)=>{
    res.send('bistro is running')
})
app.listen(port,() => {
    console.log(`Bistro Boss is sitting on port ${port}`)
})

/**
 * --------------------------------
 *      NAMING CONVENTION
 * --------------------------------
 * users : userCollection
 * app.get('/users')
 * app.get('/users/:id')
 * app.post('/users')
 * app.patch('/users/:id')
 * app.put('/users/:id')
 * app.delete('/users/:id')
*/