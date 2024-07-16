import { Router } from "express";
import * as CC from "./category.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as CV from "./category.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(CV.createCategory),
CC.createCategory)

router.put("/update/:id",
auth(validRoles.Admin),
validation(headers.headers),
multercloudiary().single("image"),
validation(CV.updateCategory),
CC.updateCategory)

router.delete("/delete/:id",
auth(validRoles.Admin),
validation(CV.deleteCategory),
CC.deleteCategory)

router.get("/",CC.getCategories)


export default router
