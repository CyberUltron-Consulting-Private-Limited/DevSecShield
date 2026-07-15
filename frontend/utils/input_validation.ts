const text_input_validation = (text: string , allowed_special_characters: string[] = []) => {
    if(text.length === 0){
        throw new Error("Input is required")
    }

    // Only block dangerous characters that could enable injection attacks
    const specialCharactersNotAllowed = ["<",">","{","}","|","`","~"]
    specialCharactersNotAllowed.forEach(char => {
        if(text.includes(char) && !allowed_special_characters.includes(char)){
            throw new Error("Character "+char+" is not allowed")
        }
    })


    return null
}

export { text_input_validation }