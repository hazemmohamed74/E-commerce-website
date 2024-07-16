import joi from "joi";
import { generalFiled } from "../../utilits/genralfield.js";



export const signUp = {
    body: joi.object().required().keys({
        name: joi.string().min(2).max(15).alphanum().required(),
        email: generalFiled.email,
        password: generalFiled.password,
        address: generalFiled.address,
        phone: generalFiled.phone,
        rePassword: joi.string().valid(joi.ref("password")),
    })
}

export const confirmEmail = {
    params: joi.object().required().keys({
        token: joi.string().required(),
        
    })
}

export const refreshtoken = {
    params: joi.object().required().keys({
        reftoken: joi.string().required(),
        
    })
}

export const forgetpassword = {
    body: joi.object().required().keys({
        email:generalFiled.email,
        
    })
}

export const resetpassword = {
    body: joi.object().required().keys({
        email:generalFiled.email,
        code: joi.string().required(),
        password: generalFiled.password
    })
}

export const signIn = {
    body: joi.object().required().keys({
        email: generalFiled.email,
        password: generalFiled.password,
    })
}