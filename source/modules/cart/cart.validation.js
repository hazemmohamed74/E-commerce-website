import joi from "joi";
import { generalFiled } from "../../utilits/genralfield.js";



export const createorder= {
    body: joi.object().keys({
        productId:generalFiled.id,
        quantity:joi.number().min(1).required(),
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