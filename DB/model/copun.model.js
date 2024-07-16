
import { Schema , Types , model } from "mongoose";

const copunSchema = new Schema ({

    code :{
        type: String,
        requeried : [true , "code is requeried"],
        unique : [true , "code is unique"],
        lowercase:true,
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    createdBy :{
        type: Types.ObjectId,
        requeried : [true , " createdBy is requeried"],
        ref : "user",
    },
    amount :{
        type: Number,
        requeried : [true , " amount is requeried"],
        ref : "user",
        min : 1 ,
        max : 100 ,
        default : 1
    },
    fromDate : {
        type: Date ,
        requeried: true
    },
    toDate : {
        type: Date ,
        requeried: true
    },
    usedBy : [{
        type: Types.ObjectId,
        ref : "user",
    },
],
    
},{
    timestamps : true 
})
const copunModel = model("copun", copunSchema)
export default copunModel