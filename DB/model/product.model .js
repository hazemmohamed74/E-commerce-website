
import { Schema , Types , model } from "mongoose";

const productSchema = new Schema ({

    tittle :{
        type: String,
        requeried : [true , "name is requeried"],
        lowercase:true,
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    slug :{                                                               //help to change the url in the search bar yo string
        type: String,
        requeried : [true , "slug is requeried"],
        minlength : 2 ,
        maxlength : 20 ,
        trim : true
    },
    createdBy :{
        type: Types.ObjectId,
        requeried : [true , "createdby is requeried"],
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
    brandId :{
        type: Types.ObjectId,
        requeried : [true , "brand is requeried"],
        ref : "brand",
    },
    image : [Object] ,
    customid:String ,
    price :{
        type: Number,
        requeried : [true , "price is requeried"],
    },
    disccount :{
        type: Number,
        default : 0,
    },
    priceAfterdiscount :{
        type: Number,
        requeried : [true , "priceAfterdiscount is requeried"],
    },
    stock :{
        type: Number,
        requeried : [true , "stock is requeried"],
    },
    avgrate :{
        type: Number,
        default : 0,
    },
    
},{
    timestamps : true 
})
const productModel = model("product", productSchema)
export default productModel