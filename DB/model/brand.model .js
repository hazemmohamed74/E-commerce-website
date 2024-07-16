
import { Schema , Types , model } from "mongoose";

const brandSchema = new Schema ({

    name :{
        type: String,
        requeried : [true , "name is requeried"],
        unique : [true , "name is unique"],
        lowercase:true,
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    slug :{                                                               //help to change the url in the search bar yo string
        type: String,
        requeried : [true , "name is requeried"],
        unique : [true , "name is unique"],
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    createdBy :{
        type: Types.ObjectId,
        requeried : [true , " createdBy is requeried"],
        ref : "user",
    },
    categoryId :{
        type: Types.ObjectId,
        requeried : [true , "categoryId is requeried"],
        ref : "category",
    },
    SubcategoryId :{
        type: Types.ObjectId,
        requeried : [true , "SubcategoryId is requeried"],
        ref : "SubCategory",
    },
    image : Object ,
    customid:String ,
    
},{
    timestamps : true 
})
const brandModel = model("brand", brandSchema)
export default brandModel