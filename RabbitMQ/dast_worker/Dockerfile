FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN apt-get update

RUN apt-get install -y git python3-pip

RUN python3 -m venv cai_env

RUN cai_env/Scripts/activate && pip install cai-framework

RUN echo -e 'OPENAI_API_KEY="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"\nANTHROPIC_API_KEY=""\nOLLAMA=""\nPROMPT_TOOLKIT_NO_CPR=1\nCAI_STREAM=false' > .env

ENV OPENAI_API_KEY="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" 

CMD [ "cai"]