const mongoose = require('mongoose')
require('dotenv').config();

mongoose.connect(process.env.MONGO_URL,{
    dbName: process.env.DB_NAME
})
.then(()=>{
    console.log('database connected')
})
.catch((err)=>{
    console.log('Error while connecting database '+err);
}
)