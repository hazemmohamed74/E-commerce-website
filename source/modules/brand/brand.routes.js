import { Router } from "express";
import * as BC from "./brand.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as BV from "./brand.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(BV.createbrand),
BC.createbrand)

router.put("/update/:id",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(BV.updatebrand),
BC.updatebrand)


export default router
