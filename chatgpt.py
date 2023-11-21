import openai
import logging

# Configure OpenAI API
api_key = "Your_OpenAI_API_KEY"
openai.api_key = api_key

def get_fix_for_vulnerability(cve_code, conversation=[]):
    # Configure logging
    logging.basicConfig(filename="logs/chatgpt.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    try:
        # Create a query for ChatGPT
        query = f"Fixes for the vulnerability ({cve_code})?"

        # Add the query to the conversation
        conversation.append({"role": "user", "content": query})

        # Send the conversation to ChatGPT
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=conversation
        )

        return response.choices[0].message["content"]

    except Exception as e:
        logging.error(f"Error in ChatGPT interaction: {str(e)}")
        return "Unable to provide a fix at this time."
