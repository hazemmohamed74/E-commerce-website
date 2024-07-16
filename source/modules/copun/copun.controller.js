import { nanoid } from "nanoid";
import SubCategoryModel from '../../../DB/model/SubCategory.model .js'
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import categoryModel from "../../../DB/model/category.model.js";
import brandModel from "../../../DB/model/brand.model .js";
import copunModel from "../../../DB/model/copun.model.js";




//**************************createcopun*************************** */
export const createcopun = asyncHandler(async(req,res,next)=>{

    const {code , amount,fromDate , toDate } = req.body
    const copunExist = await copunModel.findOne({code:code.tolowercase()})
    if (copunExist) {
        return next (new AppError("copun arleady exist "))
    }

    const copun = await copunModel.create({
        code,
        amount,
        fromDate,
        toDate,
        createdBy : req.user._id

    })
    if (!copun) {
        return next (new AppError(" fail ",409))
    }
    copun ? res.json({ msg: "done", copun }) : next(new AppError("fail", 500))
})


