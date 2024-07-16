import path from "path";
import { dbConnection } from "../DB/db.connection.js";
import dotenv from "dotenv"
dotenv.config({ path: path.resolve("config/.env") })
import authRoutes from './modules/auth/auth.routes.js'
import SubcategoryRoutes from './modules/Subcategory/Subcategory.routes.js'
import categoryRoutes from './modules/category/category.routes.js'
import brandsRoutes from './modules/brand/brand.routes.js'
import productsRoutes from './modules/product/product.routes.js'
import copunsRoutes from './modules/copun/copun.routes.js'
import cartsRoutes from './modules/cart/cart.routes.js'
import ordersRoutes from './modules/order/order.routes.js'
import reviewRoutes from './modules/review/review.routes.js'
import { validRoles,auth } from "./middleware/auth.js";

const port = process.env.PORT || 8001

export const initApp = (app,express)=>{

    app.use(express.json())
    app.use("/auths", authRoutes)
    app.use("/categories", categoryRoutes)
    app.use("/Subcategories", SubcategoryRoutes)
    app.use("/brand", brandsRoutes)
    app.use("/product", productsRoutes)
    app.use("/copun", copunsRoutes)
    app.use("/cart", cartsRoutes)
    app.use("/order", ordersRoutes)
    app.use("/review", reviewRoutes)
    // app.use("/test", auth(validRoles.User),(req,res)=>{
    //     res.json("done")
    // })
    dbConnection()
    app.listen(port, () => console.log(`Example app listening on port ${port}!`))
}