# chatbot.py
def get_bot_response(user_input: str) -> str:
    user_input = user_input.lower().strip()

    # Greeting
    if "hello" in user_input or "hi" in user_input:
        return "Hello! How can I help you today?"

    # Asking for bot's name
    elif "your name" in user_input:
        return "I'm your friendly chatbot 🤖"

    # Asking how bot is
    elif "how are you" in user_input:
        return "I'm doing great, thanks for asking! How about you?"

    # Asking for time
    elif "time" in user_input:
        from datetime import datetime
        return f"The current time is {datetime.now().strftime('%H:%M:%S')}"

    # Asking for date
    elif "date" in user_input:
        from datetime import datetime
        return f"Today’s date is {datetime.now().strftime('%Y-%m-%d')}"

    # Fallback
    else:
        return "I'm not sure about that, but I'm learning every day!"
