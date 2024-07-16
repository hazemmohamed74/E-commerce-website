
import { Schema , Types , model } from "mongoose";

const SubCategorySchema = new Schema ({

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
        requeried : [true , "createdBy is requeried"],
        ref : "user",
    },
    categoryId :{
        type: Types.ObjectId,
        requeried : [true , "categoryId is requeried"],
        ref : "category",
    },
    image : Object ,
    customid:String ,
    
},{
    toJSON: {virtuals:true},
    toObject: {virtuals:true},
    timestamps : true 
})

SubCategorySchema.virtual("brand",{
    ref:"SubCategory",
    localField:"_id" , 
    foreignField:" SubcategoryId",
})
const SubCategoryModel = model("SubCategory", SubCategorySchema)
export default SubCategoryModel