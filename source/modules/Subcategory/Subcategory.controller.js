import { nanoid } from "nanoid";
import SubCategoryModel from '../../../DB/model/SubCategory.model .js'
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import categoryModel from "../../../DB/model/category.model.js";




//**************************createSubCategory*************************** */
export const createSubCategory = asyncHandler(async(req,res,next)=>{

    const {name , categoryId } = req.body
    const categoryExist = await CategoryModel.findOne({_id:categoryId})
    const SubcategoryExist = await SubCategoryModel.findOne({name:name.tolowercase})
    if (!categoryExist) {
        return next (new AppError("category not exist ",409))
    }
    if (SubcategoryExist) {
        return next (new AppError("Subcategory alreaedy exist ",409))
    }
    const slug = slugify(name,{
        replacement:"_",
        lower:true
    })
    const customid = nanoid(4)     //name of folder of each Subcategory
    if (!req.file) {
        return next (new AppError("image is required ",409))
    }
    const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
        folder :`Ecommerce/categoriesl${categoryExist.customid}/subCategories${customid}`
    })
    const Subcategory = await SubCategoryModel.create({
        name,
        slug,
        customid,
        image:{secure_url,public_id},
        createdBy:req.user._id
    })
    if (!Subcategory) {
        await cloudinary.uploader.destroy(public_id)
        return next (new AppError("image is fail ",409))
    }
    Subcategory ? res.json({ msg: "done", Subcategory }) : next(new AppError("fail", 500))
})


//************************* updateSubCategory*************************** */
export const updateSubCategory = asyncHandler(async(req,res,next)=>{

    const {name,categoryId } = req.body
    const {id } = req.params
    const category = await categoryModel.findOne({_id:categoryId})
    if (!category) {
        return next (new AppError("category not exist  ",409))
    }
    const Subcategory = await SubCategoryModel.findOne({_id:id , createdBy:req.user._id})
    if (Subcategory) {
        return next (new AppError("Subcategory alreaedy exist or you are not the owner ",409))
    }

    if (name) {
        if (name.tolowercase()==Subcategory.name) {
            return next (new AppError(" Subcategory name match old one plz change it  ",409))
        }
        if (await SubCategoryModel.findOne({name:name.tolowercase()})) {
            return next (new AppError(" Subcategory name arleady exist ",409))
        }
        Subcategory.name=name.tolowercase()
        Subcategory. slug = slugify(name,{
            replacement:"_",
            lower:true
        })
    }
    if (req.file) {

        await cloudinary.uploader.destroy(Subcategory.image.public_id)
        const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
            folder :`Ecommerce/categoriesl${category.customid}/subCategories${Subcategory.customid}`
        })
        Subcategory.image = {secure_url,public_id}
    }
    await Subcategory.save()
    res.json({ msg: "done", Subcategory }) 
})



