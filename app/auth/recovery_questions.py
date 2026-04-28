# Predefined recovery questions. Free-text questions are easy to make trivially
# guessable ("what is my username?"), so we lock the choice down to a small
# curated set of typical knowledge-based prompts.

RECOVERY_QUESTIONS: tuple[str, ...] = (
    "What was the name of your first pet?",
    "In what city were you born?",
    "What was the make of your first car?",
    "What is your mother's maiden name?",
    "What was the name of your elementary school?",
    "What was your childhood nickname?",
)


def is_valid_question(q: str) -> bool:
    return q in RECOVERY_QUESTIONS
