import joi from "joi";
import { generalFiled } from "../../utilits/genralfield.js";



export const addreview = {
    body: joi.object().required().keys({
        comment: joi.string().min(2).max(5000).required(),
        rate: joi.number().min(1).max(100).required(),
        orderId:generalFiled.id.required(),
    }).required(),
}

export const removereview = {
    body: joi.object().required().keys({
        comment: joi.string().min(2).max(5000).required(),
        rate: joi.number().min(1).max(100).required(),
        orderId:generalFiled.id.required(),
    }).required(),
}
