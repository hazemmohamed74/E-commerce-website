import joi from "joi";
import { generalFiled } from "../../utilits/genralfield.js";



export const createbrand = {
    body: joi.object().required().keys({
        code: joi.string().min(2).max(20).alphanum().required(),
        amount: joi.number().min(1).max(100).required(),
        fromDate:joi.date().greater(Date.now()).required(),
        toDate:joi.date().greater(joi.ref("fromDate")).required(),
    }).required(),
    file:generalFiled.file.required()
}
