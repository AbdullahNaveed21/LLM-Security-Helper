This was for an LLM security class. The goal was to build something that:

Calls a third-party LLM via API 
Analyzes code for security vulnerabilities
Maps GenAI apps to OWASP and ATLAS frameworks
Tech Stack:
Frontend: Streamlit
AI Model: Llama 3.3 70B (via Groq)
Language: Python
Quick Setup
Get a FREE API key from https://console.groq.com/ (takes 2 minutes, no credit card)
Open PowerShell and run these commands:
powershell# Go to the project folder
cd C:\Users\Naveed\Desktop\llm
# Install what you need
pip install streamlit groq
# Set your API key (replace with YOUR key)
$env:GROQ_API_KEY='your-groq-key-here'
# Run 
python -m streamlit run app.py
