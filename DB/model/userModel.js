import { Schema , Types , model } from "mongoose";

const userSchema = new Schema ({

    name :{
        type: String,
        requeried : [true , "name is requeried"],
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    email :{
        type: String,
        requeried : [true , "email is requeried"],
        unique : [true , "email is unique"],
        trim : true,
        lowercase : true
    },
    password :{
        type: String,
        requeried : [true , "password is requeried"],
    },
    phone :{
        type: String,
        requeried : true 
    },
    address :{
        type: String,
        requeried : true 
    },
    forgetcode :{
        type: String,

    },
    confirmed :{
        type: Boolean,
        default : false 
    },
    loggedin :{
        type: Boolean,
        default : false 
    },
    changePasswordAt :{
        type:Date,
    },
    role :{
        type: String,
        default :"User"  ,
        enum : ["User","Admin"]
    },


},{
    timestamps : true 
})
const userModel = model("user", userSchema)
export default userModel