import api from "@/utils/interceptors"
import { handleApiError } from "./error-handler"
// ------------------------------  SAST API Routes ------------------------------

const getSastConversations = async () => {
    try {
        const response = await api.get("/sast/conversations")
        return response.data
    } catch (error) {
        console.error("Error fetching sast conversations:", error)
        handleApiError(error)
        throw error
    }
}

const deleteSastConversation = async (conversation_id: string) => {
    try {
        const response = await api.delete(`/sast/conversation/${conversation_id}`)
        return response.data
    } catch (error) {
        console.error("Error deleting sast conversation:", error)
        handleApiError(error)
        throw error
    }
}

const renameSastConversation = async (conversation_id: string, new_name: string) => {
    try {
        const response = await api.put(`/sast/conversation/${conversation_id}`, { name: new_name })
        return response.data
    } catch (error) {
        console.error("Error renaming sast conversation:", error)
        handleApiError(error)
        throw error
    }
}

export { getSastConversations, deleteSastConversation, renameSastConversation }