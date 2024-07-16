import { nanoid } from "nanoid";
import SubCategoryModel from '../../../DB/model/SubCategory.model .js'
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import categoryModel from "../../../DB/model/category.model.js";
import orderModel from "../../../DB/model/order.model .js";
import copunModel from "../../../DB/model/copun.model.js";
import cartModel from "../../../DB/model/cart.model.js";
import productModel from "../../../DB/model/product.model .js";




//**************************createorder*************************** */
export const createorder = asyncHandler(async(req,res,next)=>{

    const {productId, quantity,phone,address ,paymentmethod } = req.body
    if (req.body?.copuncode) {
        const copun = await copunModel.findOne({
            code:req.body.copuncode.tolowercase(),
            usedBy:{$nin:[req.user._id]},
        })
        if (!copun || copun.toDate < Date.now()) {
            return next (new AppError("copun not exist or expired ",409))
        }
        req.body.copun = copun;
    }
    let newProducts = []
    let flag = false
    if (!req.body.productId) {
        const cart = await copunModel.findOne({userId:req.user._Id})
        if (!cart.products) {
            return next (new AppError("select product to make order ",409))
        }
        newProducts = cart.products
        flag = true
    }else{
        newProducts = [{productId : req.body.productId,quantity:req.body.quantity}]
    }
    let finalproducts = [];
    let subprice = 0 ;
    for (const product of newProducts) {
        const checkproduct = await productModel.findOne(
            {
                _id:product.productId ,
                stock :{$gte:  product.quantity}
            });
            if (!checkproduct) {
                return next (new AppError(" product not enough ",409))
            }
            if (flag) {
                product.tittle = checkproduct.tittle ;
            product.price = checkproduct.priceAfterdiscount ;
            product.finalprice = checkproduct.priceAfterdiscount * product.quantity ;
            finalproducts.push(product);
            subprice += product.finalprice
            }
    }
    const order = await orderModel.create({
        userId : req.user._id, 
        products : finalproducts,
        copunId : req.body?.copun?._id ,
        totalprice : subprice  - subprice*((req.body?.copun.amount || 0)/100),
        phone,
        address,
        paymentmethod : "cash"
    })
    if (!order) {
        await cloudinary.uploader.destroy(public_id)
        return next (new AppError("image is fail ",409))
    }
    order ? res.json({ msg: "done", order }) : next(new AppError("fail", 500))
})


//************************* cancelOrder*************************** */
export const cancelOrder = asyncHandler(async(req,res,next)=>{
    const {orderId} = req.params
    const {reason } = req.body
    const order = await orderModel.findOne({_id:orderId,userId:req.user._id})
    if (!order) {
        return next (new AppError("order not exist  ",409))
    }
    if ((order?.status != "placed" && order?.paymentmethod == "cash" ) || (order?.status != "waitPayment" && order?.paymentmethod == "visa" ) ) {
        return next (new AppError("cannot cancel your order ",409))
    }
    const cancelorder = await orderModel.updateOne({_id:order._id},{status:"cancel",canceledby:req.user._id})
    if (!cancelorder) {
        return next (new AppError("fail to cancel order  ",409))
    }
    if (order.copunId) {
        await copunModel.updateOne({_id:order.copunId},{$pull:{canceledby:req.user._id}})   
    }
    for (const product of order.products) {
        await productModel.updateOne({_id:product.productId},{$inc:{stock:product.quantity}})
    }

    res.json({ msg: "done", cancelorder }) 
})

