let dataMethod = ["body", "params", "query", "headers", "file", "files"]
import joi from 'joi';
import { Types } from 'mongoose';


const objectIdValidation = (value, helper) => {
    return Types.ObjectId.isValid(value) ? true : helper.message("invalid id")
}
export const validation = (schema) => {

    return (req, res, next) => {

        let arrErrors = []
        dataMethod.forEach((key) => {
            if (schema[key]) {
                const { error } = schema[key].validate(req[key], { abortEarly: false })
                if (error?.details) {
                    arrErrors.push(...error.details)
                }
            }
        })
        console.log(arrErrors);
        if (arrErrors.length) {
            return res.json({ err: arrErrors.map(e => e.message) })
        }
        next()
    }
}