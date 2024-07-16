import { Router } from "express";
import * as OC from "./order.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as OV from "./order.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth([...validRoles.Admin, ...validRoles.User]),
validation(headers.headers),
validation(OV.createorder),
OC.createorder)

router.delete("/update/:id",
auth(validRoles.Admin),
validation(headers.headers),
validation(OV.cancelOrder),
OC.cancelOrder)


export default router
