
import { Schema , Types , model } from "mongoose";

const categorySchema = new Schema ({

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
        requeried : [true , "slug is requeried"],
        unique : [true , "slug is unique"],
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    createdBy :{
        type: Types.ObjectId,
        requeried : [true , "name is requeried"],
        ref : "user",
        trim : true
    },
    image : Object ,
    customid:String ,
    
},{
    toJSON: {virtuals:true},
    toObject: {virtuals:true},
    timestamps : true 
})

categorySchema.virtual("subCategory",{
    ref:"SubCategory",
    localField:"_id" , 
    foreignField:" categoryId",
})

const categoryModel = model("category", categorySchema)
export default categoryModel