// function to remove all markdown formatting from a string
export const removeMarkdownFormatting = (text: string) => {
    return text.replaceAll(/[*_~`#-]+/g, '');
}