import re

def evaluate_password_strength(password):
    # Criteria checks
    length_criteria = len(password) >= 8
    lowercase_criteria = re.search(r"[a-z]", password)
    uppercase_criteria = re.search(r"[A-Z]", password)
    number_criteria = re.search(r"\d", password)
    special_char_criteria = re.search(r"[\W_]", password)  # Covers all special characters including _

    # Score calculation
    score = sum([
        length_criteria,
        bool(lowercase_criteria),
        bool(uppercase_criteria),
        bool(number_criteria),
        bool(special_char_criteria)
    ])

    # Determine strength
    if score == 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    # Feedback
    feedback = []
    if not length_criteria:
        feedback.append("- Password should be at least 8 characters long.")
    if not lowercase_criteria:
        feedback.append("- Include at least one lowercase letter.")
    if not uppercase_criteria:
        feedback.append("- Include at least one uppercase letter.")
    if not number_criteria:
        feedback.append("- Include at least one number.")
    if not special_char_criteria:
        feedback.append("- Include at least one special character (e.g. !@#$%^&*).")

    # Output
    print("\nPassword Strength: {}".format(strength))
    if feedback:
        print("Suggestions to improve your password:")
        for item in feedback:
            print(item)

def main():
    print("Password Strength Checker")
    password = input("Enter your password: ")
    evaluate_password_strength(password)

if __name__ == "__main__":
    main()
