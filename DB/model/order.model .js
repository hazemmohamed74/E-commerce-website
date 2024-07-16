
import { Schema , Types , model } from "mongoose";

const orderSchema = new Schema ({

    userId :{
        type: Types.ObjectId,
        requeried : [true , "userId is requeried"],
        ref : "user"
    },
    products :[{ 
        tittle :{type:String,requeried:true},
        productId:{type: Types.ObjectId,ref:"product",requeried:true},
        quantity:{type: Number ,requeried:true},
        price :{type:String,requeried:true},
        finalprice :{type:String,requeried:true},
    }
],
    subprice :{type:Number},
    totalprice :{type:Number},
    copunId:{type: Types.ObjectId,ref:"product"},
    paymentmethod :{
        type: String,
        enum : ["cash","visa"],
        default : "cash",
    },
    status :{
        type: String,
        enum : [
            "placed",
            "onway",
            "delivered",
            "rejcted",
            "canceled",
            "waitPayment",
        ],
    },
    reason:String,
    canceledby:{
        type: Types.ObjectId,ref:"user"
    },
    address:{
        type:String,
        requeried:true
    },
    phone:{
        type:String,
        requeried:true
    }
    
},{
    timestamps : true 
})
const orderModel = model("order", orderSchema)
export default orderModel