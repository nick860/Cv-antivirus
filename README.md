High-School Antivirus Program
Overview
This Python 2.7-based antivirus program is a high school project designed to protect your computer from malware threats. It employs a hash-based database, virtual machine scanning, and a user-friendly GUI to enhance security.

Features
1. Hash-Based Detection
The program utilizes an SQLite3 database to store file hashes. It quickly compares incoming files against these hashes to identify known threats efficiently.

2. Virtual Machine Scanning
Suspicious files are executed in a controlled virtual machine (VM) environment. This isolates potential threats, ensuring the safety of your host system.

3. Dynamic Database Update
When a new virus is detected, its hash is added to the database. This continuous updating improves future detection capabilities.

4. User-Friendly Interface
The graphical user interface (GUI), developed with Qt 4, makes it easy for users to interact with the program and manage their security settings.

5. Advanced Hash Comparison
The program uses the ssdeep program for accurate and efficient hash comparisons, enhancing malware detection accuracy.

Getting Started
Follow these steps to get started with the antivirus program:

Prerequisites: Ensure you have Python 2.7 and Qt 4 installed on your system.

Clone the Repository: Clone this repository to your local machine.

bash
Copy code
git clone <repository-url>
Run the Program: Execute the main Python script to launch the antivirus program.

Copy code
python antivirus.py
Use the GUI: Use the user-friendly GUI to scan files, manage settings, and stay protected from malware.

Future Enhancements
Here are some potential improvements for the future:

Python Version Upgrade: Consider upgrading to a more recent Python version since Python 2.7 reached its end of life in 2020.

Database Optimization: Enhance database performance and storage efficiency.

VM Integration: Improve the virtual machine integration for comprehensive malware analysis.

Advanced Hash Algorithms: Explore the use of more advanced hash algorithms to further improve detection accuracy.

Qt Upgrade: Upgrade the GUI to a newer version of Qt for modern features and support.
