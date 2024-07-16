import joi from "joi";
import { generalFiled } from "../../utilits/genralfield.js";



export const createproduct = {
    body: joi.object().required().keys({
        tittle: joi.string().min(2).max(15).alphanum().required(),
        categoryId:generalFiled.id,
        SubcategoryId:generalFiled.id,
        brandId:generalFiled.id,
    }).required(),
    file:generalFiled.file.required()
}

// export const updatebrand = {
//     body: joi.object().required().keys({
//         name: joi.string().min(2).max(15),
//         categoryId:generalFiled.file,
//     }),
//     file:generalFiled.file
// }