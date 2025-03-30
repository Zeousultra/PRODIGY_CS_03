# Password Strength Checker

## Description
This tool evaluates the strength of a given password based on multiple criteria including length, use of uppercase and lowercase letters, numbers, and special characters. It provides instant feedback to help users improve their passwords and ensure better security.

## Features
- **Password Length**: Ensures the password has at least 8 characters.
- **Uppercase Letters**: Checks if the password contains uppercase letters (A-Z).
- **Lowercase Letters**: Checks if the password contains lowercase letters (a-z).
- **Numbers**: Verifies if the password includes numeric digits (0-9).
- **Special Characters**: Ensures the inclusion of special characters (e.g., !@#$%^&*()).

## How It Works
The script evaluates the password based on the following five criteria:

1. Length: The password must be at least 8 characters long.
2. Uppercase Letters: At least one uppercase letter (A-Z).
3. Lowercase Letters: At least one lowercase letter (a-z).
4. Numbers: At least one number (0-9).
5. Special Characters: At least one special character (e.g., !@#$%^&*()).

The password's strength is classified as:
- **Weak**: Meets fewer than 3 of the criteria.
- **Moderate**: Meets at least 3 criteria.
- **Strong**: Meets all 5 criteria.

## Installation
Make sure you have Python 3 installed. Then clone the repository:

```bash
git clone https://github.com/Zeousultra/PRODIGY_CS_03.git
cd PRODIGY_CS_03
```

## Usage
Run the script using:

```bash
python3 password_strength_checker.py
```

You will be prompted to enter a password, and the tool will analyze and rate its strength, along with feedback if improvements are needed.

### Example
```
Password Strength Checker
Enter your password: Test123

Password Strength: Moderate
Suggestions to improve your password:
- Include at least one special character (e.g. !@#$%^&*).
```

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Author
Developed by Zeousultra for educational and cybersecurity awareness purposes.

