const text_input_validation = (text: string , allowed_special_characters: string[] = []) => {
    if(text.length === 0){
        throw new Error("Input is required")
    }


    const specialCharactersNotAllowed = ["!","@","#","$","%","^","&","*","(",")","_","+","-","=","[","]{","|",";",":",",",".","<",">","?","`","~"]
    specialCharactersNotAllowed.forEach(char => {
        if(text.includes(char) && !allowed_special_characters.includes(char)){
            throw new Error("Special character "+char+" are not allowed")
        }
    })


    return null
}

export { text_input_validation }