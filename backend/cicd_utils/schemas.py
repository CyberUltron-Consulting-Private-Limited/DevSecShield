from pydantic import BaseModel

class CreateCicdConversationData(BaseModel):
    title: str
    description: str
    repository_url: str
    repository_type: str
    repository_branch: str
    repository_commit: str
    repository_commit_message: str
    repository_commit_author: str
    repository_commit_author_email: str
    repository_commit_author_date: str
    repository_commit_author_time: str