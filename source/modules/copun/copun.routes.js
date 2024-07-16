import { Router } from "express";
import * as CC from "./copun.controller.js";;
import { validation } from "../../middleware/validation.js";
import { auth,validRoles } from "../../middleware/auth.js";
import * as CV from "./copun.validation.js";
import { multercloudiary } from "../../services/multer.js";
import { headers } from "../../utilits/genralfield.js";

const router = Router()

router.post("/create",
auth(validRoles.Admin),
validation(headers.headers),
validation(CV.createcopun),
CC.createcopun)



export default router
