import { nanoid } from "nanoid";
import SubCategoryModel from '../../../DB/model/SubCategory.model .js'
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import categoryModel from "../../../DB/model/category.model.js";
import brandModel from "../../../DB/model/brand.model .js";




//**************************createbrand*************************** */
export const createbrand = asyncHandler(async(req,res,next)=>{

    const {name , categoryId,SubcategoryId } = req.body
    const categoryExist = await categoryModel.findOne({_id:categoryId})
    if (!categoryExist) {
        return next (new AppError("category not exist ",409))
    }
    const SubcategoryExist = await SubCategoryModel.findOne({name:name.tolowercase})
    if (SubcategoryExist) {
        return next (new AppError("Subcategory alreaedy exist ",409))
    }
    const brandExist = await brandModel.findOne({name:name.tolowercase})
    if (brandExist) {
        return next (new AppError("brand alreaedy exist ",409))
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
        folder :`Ecommerce/categoriesl${categoryExist.customid}/subCategories${SubcategoryExist.customid}/brands${customid}`
    })
    const brand = await brandModel.create({
        name,
        slug,
        customid,
        SubcategoryId,
        image:{secure_url,public_id},
        createdBy:req.user._id
    })
    if (!brand) {
        await cloudinary.uploader.destroy(public_id)
        return next (new AppError("image is fail ",409))
    }
    brand ? res.json({ msg: "done", brand }) : next(new AppError("fail", 500))
})


//************************* updatebrand*************************** */
export const updatebrand = asyncHandler(async(req,res,next)=>{

    const {name,categoryId ,SubcategoryId} = req.body
    const {id } = req.params
    const category = await categoryModel.findOne({_id:categoryId})
    if (!category) {
        return next (new AppError("category not exist  ",409))
    }
    const Subcategory = await SubCategoryModel.findOne({_id:SubcategoryId})
    if (Subcategory) {
        return next (new AppError("Subcategory alreaedy exist or you are not the owner ",409))
    }
    const brand = await brandModel.findOne({_id:id,createdBy:req.user})
    if (!brand) {
        return next (new AppError("brand not exist  ",409))
    }
    if (name) {
        if (name.tolowercase()==brand.name) {
            return next (new AppError(" brand name match old one plz change it  ",409))
        }
        if (await brandModel.findOne({name:name.tolowercase()})) {
            return next (new AppError(" brand name arleady exist ",409))
        }
        brand.name=name.tolowercase()
        brand. slug = slugify(name,{
            replacement:"_",
            lower:true
        })
    }
    if (req.file) {

        await cloudinary.uploader.destroy(brand.image.public_id)
        const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
            folder :`Ecommerce/categoriesl${category.customid}/subCategories${Subcategory.customid}/brands${brand.customid}`
        })
        brand.image = {secure_url,public_id}
    }
    await brand.save()
    res.json({ msg: "done", brand }) 
})

