"""Agentic SIEM Triage — entry point."""

from dotenv import load_dotenv

load_dotenv()


def main() -> None:
  print("Agentic SIEM Triage")
  print("Run the HITL dashboard: uvicorn ui.app:app --reload")


if __name__ == "__main__":
  main()
