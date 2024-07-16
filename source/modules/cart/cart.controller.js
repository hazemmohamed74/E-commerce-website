
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import cartModel from "../../../DB/model/cart.model.js";




//**************************createcart*************************** */
export const createcart = asyncHandler(async(req,res,next)=>{

    const {productId,quantity} = req.body
    const cartExist = await cartModel.findOne({userId:req.user._id})
    if (!cartExist) {
        const cart = await cartModel.create({
            userId :req.user._id,
            products:[{productId,quantity}]
        })
        res.json({ msg: "done", cart })
    }
    let flag = false ;
for (const product of cartExist.products) {
    if (product.productId.toObject()== productId) {
        product.quantity = quantity 
        flag = true
        break;
    }
    if (!flag) {
        cartExist.products.push({productId,quantity})
    }
}

    cart ? res.json({ msg: "done", cart }) : next(new AppError("fail", 500))
})


//**************************removecart*************************** */
export const removecart = asyncHandler(async(req,res,next)=>{

    const {id} = req.body
    const cart = await cartModel.findOneAndUpdate({
        userId:req.user._id ,
        "products.productId ": id
    },
    {
        $pull:{products:{productId:id}}},
        {new : true}
    )
    cart ? res.json({ msg: "done", cart }) : next(new AppError("cart clear", 500))
})

//**************************clearcart*************************** */
export const clearcart = asyncHandler(async(req,res,next)=>{

    const cart = await cartModel.findOneAndUpdate({
        userId:req.user._id ,
    },
    {
        products:[]},
        {new : true}
    )
    cart ? res.json({ msg: "done", cart }) : next(new AppError("cars not found", 500))
})


