from langchain_openai import ChatOpenAI
import json
import os

config_path = os.path.join(os.path.dirname(__file__), ".api_key.json")
with open(config_path, "r") as f:
    data = json.load(f)
    api_key = data["api_key"]
    base_url = data["base_url"]
    model_type = data["model_type"]

model = ChatOpenAI(
    model=model_type,
    api_key=api_key,
    base_url=base_url,
    timeout=200,
    max_tokens=200*1024,
    max_retries=10,
    extra_body = {"enable_thinking":False},
)
