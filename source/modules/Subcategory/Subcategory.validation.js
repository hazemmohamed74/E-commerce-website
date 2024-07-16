import joi from "joi";
import { generalFiled } from "../../utilits/genralfield.js";



export const createSubCategory = {
    body: joi.object().required().keys({
        name: joi.string().min(2).max(15).alphanum().required(),
        categoryId:generalFiled.file.required(),
    }).required(),
    file:generalFiled.file.required()
}

export const updateSubCategory = {
    body: joi.object().required().keys({
        name: joi.string().min(2).max(15),
        categoryId:generalFiled.file,
    }),
    file:generalFiled.file
}