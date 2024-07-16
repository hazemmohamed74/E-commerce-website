import { nanoid } from "nanoid";
import SubCategoryModel from '../../../DB/model/SubCategory.model .js'
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import slugify from "slugify";
import cloudinary from "../../utilits/cloudinary.js";
import categoryModel from "../../../DB/model/category.model.js";
import productModel from "../../../DB/model/product.model .js";




//**************************createproduct*************************** */
export const createproduct = asyncHandler(async(req,res,next)=>{

    const {
        tittle , 
        price,
        disccount,
        stock,
        priceAfterdiscount,
        brandId,
        categoryId,
        SubcategoryId
    } = req.body
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
    if (!req.file) {
        return next (new AppError("image is required ",409))
    }
    const customid = nanoid(4)     //name of folder of each Subcategory
    let arr = []
    let arrIds = []
    for (const file of req.file) {
        const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
            folder :`Ecommerce/categoriesl${categoryExist.customid}/subCategories${SubcategoryExist.customid}/brands${brandExist.customid}/products${customid}`
        })
        arr.push( {secure_url,public_id})
        arrIds.push( public_id)
    }
    // let image = arr;
    if (disccount) {
        const priceAfterdiscount  = price - price*((disccount||0)/100);
    }

    const product = await productModel.create({
        tittle , 
        price,
        disccount,
        stock,
        priceAfterdiscount,
        brandId,
        categoryId,
        SubcategoryId,
        image : arr , 
        createdBy:req.user._id
    })
    if (!product) {
        await cloudinary.uploader.destroy(public_id)
        return next (new AppError("image is fail ",409))
    }
    product ? res.json({ msg: "done", product }) : next(new AppError("fail", 500))
})


//************************* updateproduct*************************** */
export const updateproduct = asyncHandler(async(req,res,next)=>{

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
    const product = await productModel.findOne({_id:id,createdBy:req.user})
    if (!product) {
        return next (new AppError("product not exist  ",409))
    }
    if (name) {
        if (name.tolowercase()==product.name) {
            return next (new AppError(" product name match old one plz change it  ",409))
        }
        if (await productModel.findOne({name:name.tolowercase()})) {
            return next (new AppError(" product name arleady exist ",409))
        }
        product.name=name.tolowercase()
        product. slug = slugify(name,{
            replacement:"_",
            lower:true
        })
    }
    if (req.file) {

        await cloudinary.uploader.destroy(product.image.public_id)
        const {secure_url,public_id} = cloudinary.uploader.upload(req.file.path,{
            folder :`Ecommerce/categoriesl${category.customid}/subCategories${Subcategory.customid}/products${product.customid}`
        })
        product.image = {secure_url,public_id}
    }
    await product.save()
    res.json({ msg: "done", product }) 
})

