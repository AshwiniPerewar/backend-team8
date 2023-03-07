const mongoose = require("mongoose")


const userSchema = new mongoose.Schema({
    userId : {type : Number},
    email : {type : String },
    password : {type : String},
    mob: {type: String},
    fullName: {type: String, required: true},
    coursesApplied: {type:Array}
})

const  userModel = mongoose.model("User", userSchema)



module.exports = {
    userModel
}