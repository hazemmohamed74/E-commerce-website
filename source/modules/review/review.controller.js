import { nanoid } from "nanoid";
import SubCategoryModel from '../../../DB/model/SubCategory.model .js'
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import categoryModel from "../../../DB/model/category.model.js";
import brandModel from "../../../DB/model/brand.model .js";
import copunModel from "../../../DB/model/copun.model.js";
import productModel from "../../../DB/model/product.model .js";
import reviewModel from "../../../DB/model/review.model .js";




//**************************addreview*************************** */
export const addreview = asyncHandler(async(req,res,next)=>{

    const {comment , rate,orderId } = req.body
    const {productId} = req.params
    const product = await productModel.findOne({_id:productId})
    if (!product) {
        return next (new AppError("product not found "))
    }

    const order = await orderModel.findOne({ 
        _id:orderId,
        userId: req.user._id,
        "products.productId" : productId
    })
    if (!order) {
        return next (new AppError("order not found "))
    }
    const reviewExist = await reviewModel.findOne({ 
        userId: req.user._id,
        productId
    })
    if (reviewExist) {
        return next (new AppError("you review before "))
    }

    const review = await reviewModel.create({comment , rate,orderId , productId,userId:req.user._id})
    review ? res.json({ msg: "done", review }) : next(new AppError("fail", 500))
})

//**************************removereview*************************** */
export const removereview = asyncHandler(async(req,res,next)=>{

    const {productId , id} = req.params
    const product = await productModel.findOne({_id:productId})
    if (!product) {
        return next (new AppError("product not found "))
    }
    const review = await reviewModel.findOne({
        userId:req.user._id,
        _id:id
    })
    if (!review) {
        return next (new AppError("you review it before "))
    }
    review ? res.json({ msg: "done", review }) : next(new AppError("fail", 500))
})
