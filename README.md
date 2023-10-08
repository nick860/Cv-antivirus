# High-School Antivirus Program

## Overview

This Python 2.7-based antivirus program is a high school project designed to protect your computer from malware threats. It employs a hash-based database, virtual machine scanning, and a user-friendly GUI to enhance security.

## Features

### 1. Hash-Based Detection

The program utilizes an SQLite3 database to store file hashes. It quickly compares incoming files against these hashes to identify known threats efficiently.

### 2. Virtual Machine Scanning

Suspicious files are executed in a controlled virtual machine (VM) environment. This isolates potential threats, ensuring the safety of your host system.

### 3. Dynamic Database Update

When a new virus is detected, its hash is added to the database. This continuous updating improves future detection capabilities.

### 4. User-Friendly Interface

The graphical user interface (GUI), developed with Qt 4, makes it easy for users to interact with the program and manage their security settings.

### 5. Advanced Hash Comparison

The program uses the ssdeep program for accurate and efficient hash comparisons, enhancing malware detection accuracy.

## Getting Started

Follow these steps to get started with the antivirus program:

1. **Prerequisites**: Ensure you have Python 2.7, Qt 4, and SQLite3 installed on your system.

2. **Clone the Repository**: Clone this repository to your local machine.

   ```bash
   git clone <repository-url>
## Usage

Here are some basic instructions on how to use the antivirus program:

1. **Scanning Files**: Open the program's GUI and select the "Scan" option to scan individual files or directories for potential threats.

2. **Database Management**: Use the GUI to view and manage the database of known file hashes. You can manually update the database or set up automatic updates.

3. **Virtual Machine Analysis**: The program will automatically analyze suspicious files in a virtual machine. You can monitor the progress and view analysis reports through the GUI.
