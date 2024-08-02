const mongoose=require("mongoose");
const mongoURI="mongodb://localhost:27017/inotebook"

const connectToMongo=async ()=>{
    try{
        await mongoose.connect(mongoURI);
        console.log("connected")
        
    }
    catch (error){
        console.error("error");
    }
   
};
module.exports=connectToMongo;
