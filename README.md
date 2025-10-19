# Fusion-Crypter

# This project was created using Xanthorox AI to demonstrate what can happen when AI is misused — and to show how accessible powerful techniques can become.

# Detection Result on Xcorn Payload

<img width="1135" height="356" alt="image" src="https://github.com/user-attachments/assets/87123e9d-cc78-42b2-8287-7f3d684817a7" />



# GUI

<img width="1216" height="874" alt="image" src="https://github.com/user-attachments/assets/94303b19-56c2-459a-b4f7-f957c0945bcd" />


# Video

https://github.com/user-attachments/assets/1366d5a3-ffd3-41b0-a421-c25a619406a6



# Testing video



https://github.com/user-attachments/assets/266fe935-3df6-4c19-8c23-34ca7e69717b




# Features

Modern GUI

Clean, dark-themed interface with distinct sections for Input/Output, Cryptography, Anti-Analysis, and File Information.

Advanced Encryption

Multi-Layered Cipher: Combines a dynamically generated substitution S-Box with a multi-byte XOR cipher for obfuscation.

Polymorphic Engine: When enabled, generates unique encryption keys and junk data for each build so outputs are unique and resistant to simple signature matching.
Anti-Analysis Techniques

Junk Code Injection: Appends 4–8 KB of random data to the payload to change signatures and complicate static analysis.

API Hashing Flag: Instructs the conceptual loader stub to resolve APIs from hashed names instead of relying on static imports.

Startup Delay Flag: Adds a pause before execution to illustrate time-based sandbox evasion techniques.
Customization

Icon Changing: Replace the output executable's icon to make it appear legitimate (for demonstration only).
Version Information: Set a custom version string for the output file.


# Building from source

Prerequisites

MinGW-w64 (GCC)

Compilation

Save the source as crypter_fusion.c.

Open a command prompt in the same directory.

Run:

*x86_64-w64-mingw32-gcc crypter_fusion.c -o crypter_fusion.exe -mwindows -lcomctl32 -lcomdlg32 -lshell32 -luxtheme*

This will produce crypter_fusion.exe


# Note 

I intentionally made this low level i won't gonna post an fully fledged crypter which can be used in illigal oporations , if you have skills then modify it yourself and make it more powerfull but again i won't be responsible for this


