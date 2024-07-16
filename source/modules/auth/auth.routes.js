import { Router } from "express";
import * as AC from "./auth.controller.js";
// import { auth } from "../../middleware/auth.js";
import { validation } from "../../middleware/validation.js";
import * as AV from "./auth.validation.js";

const router = Router()

router.post("/signUp",
AC.signUp)

router.get("/confirmEmail/:token"
,validation(AV.confirmEmail),
AC.confirmEmail)

router.get("/refreshtoken:reftoken"
,validation(AV.refreshtoken),
AC.refreshtoken)

router.patch("/forget",
validation(AV.forgetpassword),
AC.forgetpassword)

router.patch("/resetpassword",
validation(AV.resetpassword),
AC.resetpassword)

router.post("/signIn",
validation(AV.signIn),
AC.signIn)




export default router