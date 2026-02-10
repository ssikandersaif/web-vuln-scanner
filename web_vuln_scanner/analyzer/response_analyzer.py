def compare_responses(base, test):
    score = 0

    if base.status_code != test.status_code:
        score += 1
    if abs(len(base.text) - len(test.text)) > 50:
        score += 1

    return score >= 1
