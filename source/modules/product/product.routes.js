import { Router } from "express";
import * as PC from "./product.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as PV from "./product.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(PV.createproduct),
PC.createproduct)

// router.put("/update/:id",
// auth(validRoles.Admin),
// validation(headers.headers),
// multercloudiary().single("image"),
// validation(PV.updatebrand),
// PC.updatebrand)


export default router
