import mongoose from "mongoose"


export const dbConnection = async () => {
    await mongoose.connect("mongodb+srv://hazem:hazem1907@cluster0.n1b3sux.mongodb.net/E_commerce").then(() => {
        console.log("db connect success");
    }).catch((err) => {
        console.log("db connect fail");
    })
}