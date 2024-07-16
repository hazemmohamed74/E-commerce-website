import joi from "joi";
import { generalFiled, headers } from "../../utilits/genralfield.js";



export const createorder = {
    body: joi.object().required().keys({
        quantity: joi.number().min(1).required(),
        productId:generalFiled.id,
        phone:generalFiled.phone ,
        address : joi.string().required(),
        paymentmethod:joi.string().valid("cash","visa").required(),
    }).with("productId","quantity")
    .required(),
    Headers : headers.headers.required(),
}

export const cancelOrder = {
    body: joi.object().required().keys({
        productId:generalFiled.id,
        paymentmethod:joi.string().valid("cash","visa").required(),
    }),
    Headers : headers.headers.required(),
}