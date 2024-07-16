import { nanoid } from "nanoid";
import userModel from "../../../DB/model/userModel.js";
import { mailFunction } from "../../services/sendmail.js";
import { AppError,asyncHandler } from "../../utilits/asyncHandler.js";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"




//**************************sign up*************************** */
export const signUp = asyncHandler(async(req,res,next)=>{

    const {email,name , password , address , phone} = req.body
    const emailExist = await userModel.findOne({email:email.tolowercase})
    if (emailExist) {
        return next (new AppError("user alreaedy exist ",409))
    }
    const token= jwt.sign({email}, process.env.SIGNATURE,{expiresIn: 60*2})

    const link = `http://localhost:8000/auths/confirmEmail/${token}`
    const reftoken= jwt.sign({email}, process.env.SIGNATURE)
    const reflink = `http://localhost:8000/auths/refreshtoken/${reftoken}`
    const emailSend = mailFunction({
        email,
        subject:"confirm email",
        html:`<a href = ${link}>confirm email</a> <br>
        <a href = ${reflink}> resend confirm email</a>`
    }) 
        if (!emailSend) {
            return next (new AppError("fail to send this email ",400))
        }
    const hash = bcrypt.hashSync(password, +process.env.SALT_ROUND)
    const user = await userModel.create({name, email, password: hash , address , phone})
    user ? res.json({ msg: "done", user }) : next(new AppError("fail", 500))
})


//**************************confirmemail*************************** */
export const confirmEmail = asyncHandler(async (req, res, next) => {
    const token = req.params.token;
    const decoded = jwt.verify(token, "hazem");
    console.log(process.env.SIGNATURE);
    if (!decoded?.email) {
        return next(new AppError("invalid token ", 404));
    }
    const user = await userModel.findOneAndUpdate(
        { email: decoded.email, confirmed: false },
        { confirmed: true },
        { new: true }
    );
    if (user) {
        const updatedUser = user.toObject();
        res.json({ msg: "done", user: updatedUser });
    } else {
        next(new AppError("fail", 500));
    }
});
//**************************refreshtoken***************************
export const refreshtoken = asyncHandler(async(req,res,next)=>{

    const reftoken = req.params
    const decoded = jwt.verify(reftoken , process.env.SIGNATURE)
    if (!decoded?.email) {
        return next (new AppError("invalid token ",404))
    }
    const user = userModel.findOne ({email : decoded.email , confirmed : false})
    if (!user) {
        return  next(new AppError("user not exist", 400))
    }
    const token= jwt.sign({email :user.email}, process.env.SIGNATURE,{expiresIn: 60*2})
    const link = `http://localhost:8000/auths/confirmEmail/${token}`
    const emailSend = mailFunction({
        email,
        subject:"confirm email",
        html:`<a href = ${link}>confirm email</a>`
    }) 
    if (!emailSend) {
        return next (new AppError("fail to send this email ",400))
    }
    user ? res.json({ msg: "done", user }) : next(new AppError("fail", 500))
})

//**************************forgetpassword********************************//
export const forgetpassword = asyncHandler(async (req, res, next) => {
    const { email } = req.body
    const userExist = await userModel.findOne({ email})
    if (!userExist) {
        return next(new AppError("user isnot exist", 404))
    }
    const code = nanoid(4)
    const emailSend = mailFunction({
        email,
        subject:"reset password",
        html:`<h1>code:${code}</h1>`
    })
    if (!emailSend) {
        return next(new AppError("email Send is fail", 404))
    }
    await userModel.updateOne({email},{forgetCode:code})

        res.json({ msg: "done" }) 
})

//**************************resetpassword********************************//
export const resetpassword = asyncHandler(async (req, res, next) => {
    const { email , code , password} = req.body
    const userExist = await userModel.findOne({ email})
    if (!userExist) {
        return next(new AppError("user isnot exist", 404))
    }
    if (userExist.forgetcode !== code) {
        return next(new AppError("code is invalid", 404))
    }
    const hash = bcrypt.hashSync(password , +process.env.SALT_ROUND)
    await userModel.updateOne({email},{password:hash ,forgetCode:"",changePasswordAt:Date.now()})
        res.json({ msg: "done" }) 
})


//**************************signIn********************************//
export const signIn = asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;
    const userExist = await userModel.findOne({ email, confirmed: true });
    
    if (!userExist) {
      return next(new AppError("User does not exist", 404));
    }
  
    const match = bcrypt.compareSync(password, userExist.password);
    
    if (!match) {
      return next(new AppError("Password does not match", 404));
    }
  
    const token = jwt.sign({ id: user._id, email, role: userExist.role }, process.env.SIGNATURE);
    
    await userModel.updateOne({ email }, { loggedin: true });
    
    res.json({ msg: "done", token });
  });
