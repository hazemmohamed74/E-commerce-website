import joi from "joi";
import { generalFiled, headers } from "../../utilits/genralfield.js";



export const createCategory = {
    body: joi.object().required().keys({
        name: joi.string().min(2).max(15).alphanum().required(),
        slug:joi.string().min(2).max(15)
    }).required(),
    file:generalFiled.file.required()
}

export const updateCategory = {
    body: joi.object().required().keys({
        name: joi.string().min(2).max(15),
    }).required(),
    params: joi.object().required().keys({
        id:generalFiled.id.required(),
    }).required(),
    file:generalFiled.file
}

export const deleteCategory = {
    params: joi.object().required().keys({
        id:generalFiled.id.required(),
    }).required(),
    headers : headers.headers.required(),
}