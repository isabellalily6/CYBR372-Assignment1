CYBR372-Assignment1 - Part 3

How it works:
The program for part 3 works by determining whether the user wants to encrypt or decrypt (by looking at the arguemnts) and then calling relevant method which performs the action. 
For encryption, the program randomly creates an IV and salt, used for encryption and creating the key from the password. The key is then created from the password, using the random salt, a fixed number of iterations and a key length. This key is then used, along with the IV and cipher algorithm, to create and initialse the cipher. The relevant input and output files are then opened to read from and write to respectively. The salt and IV are written to the output file to start with, then the cipher is used to encrypt the data, and write it to the file. 
For decryption, the program firstly opens both the input and output files. The input file is used to retrieve the salt and the IV by reading the first 16 bytes for each. The key is then created from the password, and the salt which has been retrieved. This key is then used, along with the IV and cipher algorithm, to create and initialse the cipher. The cipher is then used to decrypt the data, and write it to the output file.

Design Decisions
- Ensure correct arguments are entered
I used this design decision to ensure the user enters the correct number of arguments to reduce the amount of possible errors that could occur. The code won't and shouldn't work unless all the arguments are given hence, by checking arguemnts, this means no code is run until the correct arguments are entered.

- Display information error messages which don't give away important information
I used this design design to ensure that if an error occurs, the user can determine why the error occured. However, the error messages which are shown won't reveal important information. This is important as it means there aren't any information leaks, making the code more secure.

- Using CipherInputStream for encryption and decryption
This has been used as these cipher streams are secure and allows for easy encryption and decryption of information. 

- Generate a random IV and salt when encrypting  and creating the key using SecureRandom
The IV and salt needs to be randomly generated to ensure the code is more secure, the created key is more secure and an attacker is less likely to guess them. Due to this, I have used SecureRandom as it is a "cryptographically strong random number generator" as per https://www.baeldung.com/java-secure-random. This ensures the randomly generated IV and salt are quite strong and random, making them more secure. This also means that even when encrypting the same file with the same password, the results are different as a different IV and salt is used each time. This also means that as the salt is used to generate the key, the key is more secure.

- Store the IV and salt at the start of the encrypted file
I used this design choice because firstly, the IV and salt don't need to be encrypted. Even if an attacker has the IV and salt used for the encryption of the file and creation of the key, they still need the password and/or the key before it can be encrypted/decrypted. Due to this, the IV and salt don't need to be a secret. I also added the IV and salt to the start of the file, as this meant it was easy to read and access these values which are neccessary for decrypting files.

Why the design is secure:
My design is secure because I randomly generate the IV and salt values meaning each file, no matter if the content and password are the same, have different encryption outputs. I also use a random salt and a high number of iterations to create the key from the password, making the key hard to guess. I also ensure the error messages displayed don't reveal important information. Furthermore, CipherInputStream is used as it represents a secure cipher stream. 