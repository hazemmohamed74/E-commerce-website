import nodemailer from "nodemailer"

export const mailFunction=async({email,subject,html} ={})=>{

    const transporter = nodemailer.createTransport({
        service : "gmail",
        auth: {
        user: process.env.email_sender,
        pass: process.env.email_password,
        },
    });
        const info = await transporter.sendMail({
        from: '"Fred Foo 👻" <hazemmh2020@gmail.com>', 
        to: email, 
        subject:subject? subject: "Hello ✔", 
        html:html?html: "<b>Hello world?</b>", 
        });
        // console.log(info);
        if (info.accepted.length>0) {
            return true 
        }
        return false 
    
}