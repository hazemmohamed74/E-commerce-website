import joi from "joi";

const objectIdValidation = (value, helper) => {
    return Types.ObjectId.isValid(value) ? true : helper.message("invalid id")
}

export const generalFiled = {
    email: joi.string().email({ tlds: { allow: ["outlook", "com"] }, minDomainSegments: 2 }).required(),
    password: joi.string().regex(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/).required(),
    rePassword: joi.string().valid(joi.ref("password")).required(),
    industry: joi.string().required(),
    phone: joi.string().required(),
        address: joi.string().required(),
        numberOfEmployees:joi.string().min(11).max(20),
    file: joi.object().keys({
        size: joi.number().positive().required(),
        path: joi.string().required(),
        filename: joi.string().required(),
        destination: joi.string().required(),
        mimetype: joi.string().required(),
        encoding: joi.string().required(),
        originalname: joi.string().required(),
        fieldname: joi.string().required(),
        // categoryId: joi.string().required(),
    }),
    id:joi.string().custom(objectIdValidation)
};
export const headers = {
    headers: joi.object({
        'cache-control': joi.string(),
        'postman-token': joi.string(),
        'content-type': joi.string(),
        'content-length': joi.string(),
        host: joi.string(),
        'user-agent': joi.string(),
        accept: joi.string(),
        'accept-encoding': joi.string(),
        connection: joi.string(),
        token: joi.string().required()
    })
}
