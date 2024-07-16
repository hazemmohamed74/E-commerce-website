import { nanoid } from "nanoid";
import categoryModel from "../../../DB/model/category.model.js";
import { mailFunction } from "../../services/sendmail.js";
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import SubCategoryModel from "../../../DB/model/SubCategory.model .js";
import brandModel from "../../../DB/model/brand.model .js";




//**************************createCategory*************************** */
export const createCategory = asyncHandler(async(req,res,next)=>{

    const {name } = req.body
    const categoryExist = await categoryModel.findOne({name:name.tolowercase})
    if (categoryExist) {
        return next (new AppError("category alreaedy exist ",409))
    }
    const slug = slugify(name,{
        replacement:"_",
        lower:true
    })
    const customid = nanoid(4)     //name of folder of each category
    if (!req.file) {
        return next (new AppError("image is required ",409))
    }
    const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
        folder :`Ecommerce/categoryl${customid}`
    })
    const category = await categoryModel.create({
        name,
        slug,
        customid,
        image:{secure_url,public_id},
        createdBy:req.user._id
    })
    if (!category) {
        await cloudinary.uploader.destroy(public_id)
        return next (new AppError("image is fail ",409))
    }
    category ? res.json({ msg: "done", category }) : next(new AppError("fail", 500))
})


//************************* updateCategory*************************** */
export const updateCategory = asyncHandler(async(req,res,next)=>{

    const {name } = req.body
    const {id } = req.params
    const category = await categoryModel.findOne({_id:id , createdBy:req.user._id})
    if (category) {
        return next (new AppError("category alreaedy exist or you are not the owner ",409))
    }

    if (name) {
        if (name.tolowercase()==category.name) {
            return next (new AppError(" category name match old one plz change it  ",409))
        }
        if (await categoryModel.findOne({name:name.tolowercase()})) {
            return next (new AppError(" category name arleady exist ",409))
        }
        category.name=name.tolowercase()
        category. slug = slugify(name,{
            replacement:"_",
            lower:true
        })
    }
    if (req.file) {

        await cloudinary.uploader.destroy(category.image.public_id)
        const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
            folder :`Ecommerce/categoriesl${category.customid}`
        })
        category.image = {secure_url,public_id}
    }
    await category.save()
    res.json({ msg: "done", category }) 
})


//**************************getCategories*************************** */
export const getCategories = asyncHandler(async(req,res,next)=>{

    const categories = await categoryModel.find.populate([{
        path:"subCategory",
        populate:[{
            path:"brand"
        }]
    }])
    res.json({msg:"done",categories})
})


//**************************deleteCategory*************************** */
export const deleteCategory = asyncHandler(async(req,res,next)=>{
    const {id} = req.params.id

//deleted from db
    const category = await categoryModel.findByOneAndDelete({id:_id,createdBy:req.user._id})
    if (!category) {
        return next (new AppError("category not exist or you are not the owner ",409))
    }
    const relatedSubcategory = await SubCategoryModel.deleteMany({categoryId:id})
    if (relatedSubcategory.deletedCount) {
        return next (new AppError("category not delete ",409))
    }
    const relatedbrand = await brandModel.deleteMany({categoryId:id})
    if (relatedbrand.deletedCount) {
        return next (new AppError("brand not delete ",409))
    }

    //delete from cloudinary
    await cloudinary.api.delete_resources_by_prefix(`Ecommerce/categoryl${customid}`)
    await cloudinary.api.delete_folder(`Ecommerce/categoryl${customid}`)
    
    res.json({msg:"done"})
})
