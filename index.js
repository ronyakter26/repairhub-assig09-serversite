import express from "express";
import cors from "cors";
import { MongoClient } from 'mongodb';

const PORT =5000;
const app=express();
app.use(express.json());
const client = new MongoClient("mongodb://repairhub-assig09:orhF68nHiShx1uRm@ac-ng0lbcw-shard-00-00.vss3zq2.mongodb.net:27017,ac-ng0lbcw-shard-00-01.vss3zq2.mongodb.net:27017,ac-ng0lbcw-shard-00-02.vss3zq2.mongodb.net:27017/?ssl=true&replicaSet=atlas-c3wrb6-shard-0&authSource=admin");
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}
app.listen(PORT,()=>{
    console.log(`server is running on port ${PORT}`)
})
