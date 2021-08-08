CYBR372-Assignment1 - Part 2

How it works:
The program for part 2 works by determining whether the user wants to encrypt or decrypt (by looking at the arguemnts) and then calling relevant method which performs the action. 
For encryption, the program decrypts the key given by the user and randomly generates an IV. These are used, along with the cipher algorithm, to create and initialse the cipher. The relevant input and output files are then opened to read from and write to respectively. The IV is written to the output file to start with, then the cipher is used to encrypt the data, and write it to the file. 
For decryption, the program first base64 decodes the key and then opens both the input and output files. The first 16 bytes of the file are read to retrieve the IV value, and this value is used, along with the key and cipher algorithm, to create the cipher. The cipher is then used to decrypt the data, and write it to the output file. 

Design Decisions
- Ensure correct arguments are entered
I used this design decision to ensure the user enters the correct number of arguments to reduce the amount of possible errors that could occur. The code won't and shouldn't work unless all the arguments are given hence, by checking arguemnts, this means no code is run until the correct arguments are entered.

- Display information error messages which don't give away important information
I used this design design to ensure that if an error occurs, the user can determine why the error occured. However, the error messages which are shown won't reveal important information. This is important as it means there aren't any information leaks, making the code more secure.

- Using CipherInputStream for encryption and decryption
This has been used as these cipher streams are secure and allows for easy encryption and decryption of information. 

- Generate a random IV when encrypting using SecureRandom
The IV needs to be randomly generated to ensure the code is more secure and an attacker is less likely to guess them. Due to this, I have used SecureRandom as it is a "cryptographically strong random number generator" as per https://www.baeldung.com/java-secure-random. This ensures the randomly generated IV is quite strong and random, making them more secure. This also means that even when encrypting the same file with the same password, the results are different as a different IV is used each time. 

- Store the IV at the start of the encrypted file
I used this design choice because firstly, the IV doesn't need to be encrypted. Even if an attacker has the IV used for the encryption of the file, they still need the key before it can be encrypted/decrypted. Due to this, the IV doesn't need to be a secret. I also added the IV to the start of the file, as this meant it was easy to read and access which is neccessary, as the IV is needed to decrypt the file.

Why the design is secure:
My design is secure because I randomly generate the IV values meaning each file, no matter if the content and key are the same, have different encryption outputs. I also ensure the error messages displayed don't reveal important information. Furthermore, CipherInputStream is used as it represents a secure cipher stream. 

