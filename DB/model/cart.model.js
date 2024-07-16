
import { Schema , Types , model } from "mongoose";

const cartSchema = new Schema ({

    userId :{
        type: Types.ObjectId,
        requeried : [true , "userId is requeried"],
        ref : "user"
    },
    products :[{ 
        productId:{type: Types.ObjectId,ref:"product",requeried:true},
        quantity:{type: Number ,requeried:true}
    }
]
},{
    timestamps : true 
})

const cartModel = model("cart", cartSchema)
export default cartModel