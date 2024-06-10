import re
from datetime import datetime

def check_password_strength(password):
    # Define criteria using regular expressions
    length_criteria = len(password) >= 8
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    digit_criteria = re.search(r'\d', password) is not None
    special_char_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    # Check how many criteria are met
    criteria_met = sum([length_criteria, lowercase_criteria, uppercase_criteria, digit_criteria, special_char_criteria])

    # Provide feedback based on the criteria met
    if criteria_met == 5:
        strength = "Very Strong"
    elif criteria_met == 4:
        strength = "Strong"
    elif criteria_met == 3:
        strength = "Moderate"
    elif criteria_met == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Provide detailed feedback
    feedback = []
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not lowercase_criteria:
        feedback.append("Password should contain at least one lowercase letter.")
    if not uppercase_criteria:
        feedback.append("Password should contain at least one uppercase letter.")
    if not digit_criteria:
        feedback.append("Password should contain at least one digit.")
    if not special_char_criteria:
        feedback.append("Password should contain at least one special character.")

    return strength, feedback

def log_feedback(password, strength, feedback):
    # Log feedback into a file
    with open("password_feedback.log", "a") as log_file:
        log_file.write(f"Timestamp: {datetime.now()}\n")
        log_file.write(f"Password: {password}\n")
        log_file.write(f"Strength: {strength}\n")
        log_file.write("Feedback:\n")
        for comment in feedback:
            log_file.write(f"  - {comment}\n")
        log_file.write("\n")

# Example usage
password = input("Enter a password to check its strength: ")
strength, feedback = check_password_strength(password)

print(f"Password Strength: {strength}")
for comment in feedback:
    print(comment)

# Log the feedback
log_feedback(password, strength, feedback)
