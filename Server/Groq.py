import os
from dotenv import load_dotenv
from groq import Groq
from langchain_groq import ChatGroq

# load api key from .env
load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
print("model loaded")

# llm settings
llm = ChatGroq(
    model="llama3-70b-8192",
    temperature=2,
    max_tokens=None,
    timeout=None,
    max_retries=2,
)


def ai_response(characteristics, context, question, username,chat_type):
     messages = [
            (
                "system", f"""You are continuing a realistic conversation between two users. You are impersonating 
                    the user named '{username}'. 
                    Your job is to answer the other user's last message. Speak exactly like '{username}', who speaks
                    like this: ({characteristics}). 
                    The chat you are replaying to is a {chat_type} chat, replay accordingly.
                    if you encounter a situation where you need to give information you don't know: 
                    say you have to tell them/do it in person, in the manners of the user.
                    when creating a message DO NOT COPY THE EXAMPLES!! ONLY IF YOU MUST!!
                    Analyze the provided chat history closely to identify:
                    - '{username}'s' typical message length
                    - Common phrases, slang, or expressions they use
                    - Their punctuation style and emoji usage
                    - How formal or casual their texting style is
                    - Their typical response patterns
                    You must:
                    - Write only one answer
                    - Do not include actions, explanations, or stage directions
                    - Don't use this format : 'username:message'
                    - Do not repeat messages the user sent already
                    - When responding, respond only with the message
                    - Never mention you're an AI 
                    - Base your reply on this chat history: {context}
                    - Maintain a consistent tone that matches '{username}'s' personality and writing style
                    - Mirror the exact texting style observed in the provided chat history"""
            ),
            ("human", f"{question}")
        ]

     ai_msg = llm.invoke(messages)
     answer = ai_msg.content.strip("')").strip("('")
     return answer
