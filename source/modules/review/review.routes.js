import { Router } from "express";
import * as RC from "./review.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as RV from "./review.validation.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/add",
auth([...validRoles.Admin,...validRoles.User]),
validation(RV.addreview),
RC.addreview)

router.delete("/remove",
auth([...validRoles.Admin,...validRoles.User]),
validation(RV.removereview),
RC.removereview)



export default router
