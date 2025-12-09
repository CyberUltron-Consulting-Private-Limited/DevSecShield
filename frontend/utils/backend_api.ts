import api from "@/utils/interceptors"
import { handleApiError } from "./error-handler"
import { toast } from "sonner"


// ------------------------------  SAST API Routes ------------------------------

export interface SastConversation {
    id: number
    title: string
    created_at: string
    scan_status: string
}

const getSastConversations = async (): Promise<SastConversation[]> => {
    try {
        const response = await api.get("/sast/conversations")
        toast.success("Sast conversations fetched successfully")
        return response.data
    } catch (error) {
        console.error("Error fetching sast conversations:", error)
        handleApiError(error)
        throw error
    }
}

const deleteSastConversation = async (conversation_id: number) => {
    try {
        const response = await api.delete(`/sast/conversation/${conversation_id}`)
        toast.success("Sast conversation deleted successfully")
        return response.data
    } catch (error) {
        console.error("Error deleting sast conversation:", error)
        handleApiError(error)
        throw error
    }
}

const renameSastConversation = async (conversation_id: number, title: string) => {
    try {
        const response = await api.put(`/sast/conversation/${conversation_id}`, { title: title })
        toast.success("Sast conversation renamed successfully")
        return response.data
    } catch (error) {
        console.error("Error renaming sast conversation:", error)
        handleApiError(error)
        throw error
    }
}

export { getSastConversations, deleteSastConversation, renameSastConversation }