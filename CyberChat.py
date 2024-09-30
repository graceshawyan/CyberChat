#Grace Yan
#CyberChat Project

import tkinter as tk
from tkinter.scrolledtext import ScrolledText

#Global variables to manage chatbot state
chatbot_state = {
    'current_function': None,
    'awaiting_input': False,
    'answer_function': None,
}

#GUI

def slow_print_gui(text):
    chat_window.insert(tk.END, text + '\n')
    chat_window.see(tk.END)  # Scroll to the end

def main_menu_gui():
    slow_print_gui("\nWelcome to the Cybersecurity Chatbot!")
    slow_print_gui("Please select a topic to learn about:")
    topics = {
        '1': 'Password Security',
        '2': 'Phishing Attacks',
        '3': 'Malware',
        '4': 'Network Security',
        '5': 'Social Engineering',
        '6': 'Encryption',
        '7': 'Identity Theft',
        '8': 'Safe Browsing Practices',
        '9': 'Mobile Device Security',
        '10': 'Cloud Security',
        '11': 'Exit'
    }
    for key, value in topics.items():
        slow_print_gui(f"{key}. {value}")
    slow_print_gui("\nEnter the number of your choice:")
    chatbot_state['current_function'] = 'main_menu'
    chatbot_state['awaiting_input'] = True

#Menu choices
def process_main_menu_choice(user_input):
    choice = user_input.strip()
    chatbot_state['awaiting_input'] = False
    if choice == '1':
        password_security()
    elif choice == '2':
        phishing_attacks()
    elif choice == '3':
        malware()
    elif choice == '4':
        network_security()
    elif choice == '5':
        social_engineering()
    elif choice == '6':
        encryption()
    elif choice == '7':
        identity_theft()
    elif choice == '8':
        safe_browsing()
    elif choice == '9':
        mobile_security()
    elif choice == '10':
        cloud_security()
    elif choice == '11':
        exit_chatbot()
    else:
        invalid_choice()
        main_menu_gui()

#Choices 1-10
def password_security():
    slow_print_gui("\n--- Password Security ---")
    slow_print_gui("""
Password security involves creating strong, unique passwords and keeping them confidential.
Tips:
- Use a mix of letters, numbers, and special characters.
- Avoid using personal information.
- Use different passwords for different accounts.
- Consider using a reputable password manager.
""")
    question = "Which of the following is a strong password?\nA) password123\nB) JohnSmith\nC) P@55w0rd!\nD) 123456"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'password_security'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_password_security_answer

def check_password_security_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'C':
        slow_print_gui("Correct! 'P@55w0rd!' is a strong password.")
    else:
        slow_print_gui("Incorrect. The correct answer is C.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def phishing_attacks():
    slow_print_gui("\n--- Phishing Attacks ---")
    slow_print_gui("""
Phishing is a type of social engineering attack often used to steal user data.
Tips:
- Be cautious of unexpected emails asking for personal information.
- Check the sender's email address carefully.
- Do not click on suspicious links or attachments.
""")
    question = "What is the primary goal of a phishing attack?\nA) To improve network speed\nB) To steal personal information\nC) To update software\nD) To protect user data"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'phishing_attacks'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_phishing_attacks_answer

def check_phishing_attacks_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'B':
        slow_print_gui("Correct! Phishing attacks aim to steal personal information.")
    else:
        slow_print_gui("Incorrect. The correct answer is B.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def malware():
    slow_print_gui("\n--- Malware ---")
    slow_print_gui("""
Malware is malicious software designed to harm or exploit any programmable device or network.
Types:
- Viruses
- Worms
- Trojans
- Ransomware
""")
    question = "Which type of malware locks your files and demands payment?\nA) Virus\nB) Worm\nC) Ransomware\nD) Spyware"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'malware'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_malware_answer

def check_malware_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'C':
        slow_print_gui("Correct! Ransomware locks your files until a ransom is paid.")
    else:
        slow_print_gui("Incorrect. The correct answer is C.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def network_security():
    slow_print_gui("\n--- Network Security ---")
    slow_print_gui("""
Network security protects the usability and integrity of your network and data.
Practices:
- Firewalls
- Intrusion detection systems
- Regular software updates
- Strong authentication mechanisms
""")
    question = "What is the primary function of a firewall?\nA) To encrypt data\nB) To block unauthorized access\nC) To store passwords\nD) To detect viruses"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'network_security'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_network_security_answer

def check_network_security_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'B':
        slow_print_gui("Correct! Firewalls block unauthorized access to networks.")
    else:
        slow_print_gui("Incorrect. The correct answer is B.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def social_engineering():
    slow_print_gui("\n--- Social Engineering ---")
    slow_print_gui("""
Social engineering involves manipulating people into giving up confidential information.
Techniques:
- Pretexting
- Baiting
- Tailgating
- Phishing
""")
    question = "Social engineering attacks rely heavily on what?\nA) Software vulnerabilities\nB) Human interaction\nC) Hardware failures\nD) Network speeds"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'social_engineering'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_social_engineering_answer

def check_social_engineering_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'B':
        slow_print_gui("Correct! They rely on human interaction and manipulation.")
    else:
        slow_print_gui("Incorrect. The correct answer is B.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def encryption():
    slow_print_gui("\n--- Encryption ---")
    slow_print_gui("""
Encryption is the process of converting data into a coded form to prevent unauthorized access.
Types:
- Symmetric encryption
- Asymmetric encryption
Applications:
- Secure communications
- Protecting sensitive data
""")
    question = "Which encryption uses a pair of keys (public and private)?\nA) Symmetric\nB) Asymmetric\nC) Hashing\nD) SSL"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'encryption'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_encryption_answer

def check_encryption_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'B':
        slow_print_gui("Correct! Asymmetric encryption uses a pair of keys.")
    else:
        slow_print_gui("Incorrect. The correct answer is B.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def identity_theft():
    slow_print_gui("\n--- Identity Theft ---")
    slow_print_gui("""
Identity theft occurs when someone uses your personal information without your permission.
Prevention Tips:
- Protect your Social Security number.
- Shred sensitive documents.
- Monitor financial statements regularly.
- Use secure passwords and change them regularly.
""")
    question = "Which action can help prevent identity theft?\nA) Sharing personal info on social media\nB) Ignoring bank statements\nC) Using strong, unique passwords\nD) Clicking unknown email links"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'identity_theft'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_identity_theft_answer

def check_identity_theft_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'C':
        slow_print_gui("Correct! Strong passwords help protect your personal information.")
    else:
        slow_print_gui("Incorrect. The correct answer is C.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def safe_browsing():
    slow_print_gui("\n--- Safe Browsing Practices ---")
    slow_print_gui("""
Safe browsing involves being cautious and adopting practices that protect you online.
Tips:
- Use HTTPS websites.
- Keep your browser updated.
- Beware of pop-ups and ads.
- Do not download files from untrusted sources.
""")
    question = "What indicates a secure website connection?\nA) 'http' in the URL\nB) 'https' in the URL\nC) A misspelled domain\nD) No padlock icon"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'safe_browsing'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_safe_browsing_answer

def check_safe_browsing_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'B':
        slow_print_gui("Correct! 'https' indicates a secure, encrypted connection.")
    else:
        slow_print_gui("Incorrect. The correct answer is B.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def mobile_security():
    slow_print_gui("\n--- Mobile Device Security ---")
    slow_print_gui("""
Mobile security protects smartphones and tablets from threats.
Tips:
- Set a screen lock (PIN, password, fingerprint).
- Install apps only from trusted sources.
- Keep your device's software updated.
- Be cautious when connecting to public Wi-Fi.
""")
    question = "Which practice enhances mobile device security?\nA) Using default passwords\nB) Downloading apps from any website\nC) Regularly updating the operating system\nD) Disabling screen locks"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'mobile_security'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_mobile_security_answer

def check_mobile_security_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'C':
        slow_print_gui("Correct! Updating OS patches security vulnerabilities.")
    else:
        slow_print_gui("Incorrect. The correct answer is C.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def cloud_security():
    slow_print_gui("\n--- Cloud Security ---")
    slow_print_gui("""
Cloud security involves protecting data and systems in the cloud environment.
Best Practices:
- Use strong authentication (MFA).
- Encrypt sensitive data.
- Regularly back up data.
- Understand shared responsibility models.
""")
    question = "What does MFA stand for in cloud security?\nA) Multi-Factor Authentication\nB) Managed File Access\nC) Multiple Firewall Assessment\nD) Main Frame Application"
    slow_print_gui(question)
    slow_print_gui("Your answer (A/B/C/D):")
    chatbot_state['current_function'] = 'cloud_security'
    chatbot_state['awaiting_input'] = True
    chatbot_state['answer_function'] = check_cloud_security_answer

def check_cloud_security_answer(user_input):
    answer = user_input.strip().upper()
    if answer == 'A':
        slow_print_gui("Correct! MFA adds extra layers of authentication.")
    else:
        slow_print_gui("Incorrect. The correct answer is A.")
    chatbot_state['awaiting_input'] = False
    chatbot_state['answer_function'] = None
    main_menu_gui()

def exit_chatbot():
    slow_print_gui("\nThank you for using the Cybersecurity Chatbot. Stay safe online!")
    root.after(2000, root.quit)  # Delay exit to allow the user to read the message

def invalid_choice():
    slow_print_gui("\nInvalid choice. Please enter a number corresponding to the topics listed.")

#No message entered
def send_message(event=None):
    user_input = entry_field.get()
    chat_window.insert(tk.END, "You: " + user_input + '\n')
    chat_window.see(tk.END)
    entry_field.delete(0, tk.END)

    if chatbot_state['current_function'] == 'main_menu' and chatbot_state['awaiting_input']:
        process_main_menu_choice(user_input)
    elif chatbot_state['awaiting_input'] and chatbot_state['answer_function']:
        chatbot_state['answer_function'](user_input)
    else:
        slow_print_gui("Please select a topic by entering the corresponding number.")
        main_menu_gui()

#Initialize Tkinter GUI
root = tk.Tk()
root.title("Cybersecurity Chatbot")

#Set window size, making it resizable
root.geometry("600x500")
root.resizable(True, True)

#Grid layout
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

#Chat window
chat_window = ScrolledText(root, wrap=tk.WORD)
chat_window.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

#Entry field
entry_field = tk.Entry(root, width=80)
entry_field.grid(row=1, column=0, padx=10, pady=(0,10), sticky="ew")
entry_field.bind("<Return>", send_message)

#Send button
send_button = tk.Button(root, text="Send", command=send_message)
send_button.grid(row=1, column=1, padx=10, pady=(0,10), sticky="ew")

#Display of main menu; starts chatbot
main_menu_gui()

root.mainloop()
