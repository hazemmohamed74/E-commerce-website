import { Router } from "express";
import * as CC from "./cart.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as CV from "./cart.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth(validRoles.Admin),
validation(CV.createcart),
CC.createcart)

// router.put("/update/:id",
// auth(validRoles.Admin),
// validation(headers.headers),
// multercloudiary().single("image"),
// validation(PV.updatebrand),
// PC.updatebrand)


export default router
