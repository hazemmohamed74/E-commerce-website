import { Router } from "express";
import * as SC from "./Subcategory.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as SV from "./Subcategory.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(SV.createSubCategory),
SC.createSubCategory)

router.put("/update/:id",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(SV.updateSubCategory),
SC.updateSubCategory)


export default router
