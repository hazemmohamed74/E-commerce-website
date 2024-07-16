
import { Schema , Types , model } from "mongoose";

const reviewSchema = new Schema ({
    comment:{
        type:String,
        requeried:true
    },
    rate:{
        type:Number,
        requeried:true,
        min : 1,
        max: 5 
    },
    userId :{
        type: Types.ObjectId,
        requeried : [true , "userId is requeried"],
        ref : "user"
    },
    productId :{
        type: Types.ObjectId,
        requeried : [true , "productId is requeried"],
        ref : "product"
    },
    orderId :{
        type: Types.ObjectId,
        requeried : [true , "orderId is requeried"],
        ref : "order"
    },
    
},{
    timestamps : true 
})
const reviewModel = model("review", reviewSchema)
export default reviewModel