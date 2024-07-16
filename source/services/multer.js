import multer from 'multer'
export let validExtintion = {
    image: ["image/jpeg","image/png"],
    audio :["audio/mp4"]
}
export const multercloudiary= (customValidation) => {

    if (!customValidation) {
        customValidation == validExtintion.image
    }
    const storage = multer.diskStorage({})
const filefilter = function(req , file , cb){
    console.log(file.mimetype);
    if ( customValidation.includes(file.mimetype)) {
        return cb(null,true) }
}

const upload = multer({storage,filefilter})
return upload
}