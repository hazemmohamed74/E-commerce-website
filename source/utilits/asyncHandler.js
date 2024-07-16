export const asyncHandler = (fn) => {
    return (req, res, next) => {
        fn(req,res,next).catch((err) => {
            
            next(err)
        })
    }

}


export class AppError extends Error {
    constructor(message, statusCode) {
        super(message)
        this.statusCode = statusCode
    }
}