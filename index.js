const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config()
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);
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
    // await client.connect();
    client.connect();
    
    const usersCollection = client.db("BistroDb").collection("users");
    const menuCollection = client.db("BistroDb").collection("menu");
    const reviewCollection = client.db("BistroDb").collection("reviews");
    const cartCollection = client.db("BistroDb").collection("carts");
    const paymentCollection = client.db("BistroDb").collection("payments");

    // jwt api

    app.post('/jwt', (req, res) =>{
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '1h'
      })
      res.send({ token });
    })
    // Warning: use verifyJWT before using verifyAdmin
    const verifyAdmin = async(req, res, next) => {
      const email = req.decoded.email
      const query = { email : email}
      const user = await usersCollection.findOne(query)
      if(user?.role !== 'admin'){
        return res.status(403).send({error: true , message: 'forbidden message'})
      }
      next()
    }

    // user related api's

    /** APi secure only admin can access
     * 1. Do not show secure links to those who should not see the links
     * 2. use jwt token : verifyJWT
     * 3. use verifyAdmin middleware
     * 
     * * */

    app.get('/users',verifyJWT,verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    })

    app.post('/users',async(req, res) => {
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

    app.post('/menu',verifyJWT,verifyAdmin, async(req,res)=> {
      const newItem = req.body
      const result = await menuCollection.insertOne(newItem)
      res.send(result)
    })

    app.delete('/menu/:id', verifyJWT, verifyAdmin,  async(req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) }
      const result = await menuCollection.deleteOne(query)
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

    // create payment intent

    app.post('/create-payment-intent',verifyJWT, async (req, res) => {
      const { price } = req.body;
      const amount = parseInt(price*100) 
      //or
      // const amount = Math.round(price*100)
      // console.log(price, amount)
      const paymentIntent = await stripe.paymentIntents.create({
        amount: amount,
        currency: "usd",
        payment_method_types: ['card']
      })
      res.send({clientSecret: paymentIntent.client_secret})
    })

    //advanced code from with error checking  for /create-payment-intent up above
    // app.post('/create-payment-intent', verifyJWT, async (req, res) => {
    //   const { price } = req.body;
     // const amount = Math.round(price*100) 
    //   // Validate the price value
    //   if (isNaN(price) || price <= 0) {
    //     return res.status(400).json({ error: 'Invalid price value' });
    //   }
    
    //   const amount = price * 100;
    
    //   try {
    //     const paymentIntent = await stripe.paymentIntents.create({
    //       amount: amount,
    //       currency: 'usd',
    //       payment_method_types: ['card']
    //     });
    //     res.send({ clientSecret: paymentIntent.client_secret });
    //   } catch (error) {
    //     // Handle Stripe API errors
    //     res.status(500).json({ error: 'Failed to create payment intent' });
    //   }
    // });
    

    // payment related api

    app.post('/payments',verifyJWT, async(req, res) => {
      const payment = req.body;
      const insertResult = await paymentCollection.insertOne(payment)
      const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }
      const deleteResult = await cartCollection.deleteMany(query)

      res.send({insertResult, deleteResult})
    })
    // admin -only api's
    app.get('/admin-stats',verifyJWT,verifyAdmin, async(req, res) =>{
      const users = await usersCollection.estimatedDocumentCount();
      const products = await menuCollection.estimatedDocumentCount();
      const orders = await paymentCollection.estimatedDocumentCount();

      // best way to get sum of a field is to ue group and sum operator
      /*
      await paymentCollection.aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: '$price' }
          }
        }
      ]).toArray((err, result) => {
        if (err) {
          console.error('Error executing aggregation:', err);
          res.status(500).send('Error executing aggregation');
          return;
        }
  
        if (result.length === 0) {
          res.status(404).send('No payments found');
          return;
        }
  
        const totalPrice = result[0].total;
        res.json({ totalPrice });
      });
      */

    /**
     * Bangla system
     */
      const payments = await paymentCollection.find().toArray();
      const revenue = payments.reduce((sum, payment)=> sum + payment.price,0)
      // console.log({
      //   users,
      //   products,
      //   orders,
      //   revenue
      // })
      // console.log({users,
      //   products,
      //   orders,
      //   revenue})
      res.send({
        users,
        products,
        orders,
        revenue
      })
    })
       /**
     * ---------------
     * BANGLA SYSTEM(second best solution) for loading revenue calculating payments
     * ---------------
     * 1. load all payments
     * 2. for each payment, get the menuItems array
     * 3. for each item in the menuItems array get the menuItem from the menu collection
     * 4. put them in an array: allOrderedItems
     * 5. separate allOrderedItems by category using filter
     * 6. now get the quantity by using length: pizzas.length
     * 7. for each category use reduce to get the total amount spent on this category
     * 
    */
    app.get('/order-stats', verifyJWT, verifyAdmin, async(req,res) =>{
      const pipeline = [
        {
          $lookup: {
            from: 'menu',
            localField: 'menuItems',
            foreignField: '_id',
            as: 'menuItemsData'
          }
        },
        {
          $unwind: '$menuItemsData'
        },
        {
          $group: {
            _id: '$menuItemsData.category',
            count: { $sum: 1 },
            total: { $sum: '$menuItemsData.price' },

          }
        },
        {
          $project: {
            category: '$_id',// this represents _id in group and these are not flexible
            // you have to use specific mongodb predefined names
            count: 1,
            total: { $round: ['$total', 2] },
            _id: 0
          }
        }
      ];

      const result = await paymentCollection.aggregate(pipeline).toArray()
      res.send(result)

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