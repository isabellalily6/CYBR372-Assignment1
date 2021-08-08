CYBR372-Assignment1 - Part 1

How it works:
The program for part 1 works by determining whether the user wants to encrypt or decrypt (by looking at the arguemnts) and then calling relevant method which performs the action. 
For encryption, the program randomly generates a key and an IV and uses them, along with the cipher algorithm, to create and initialse the cipher. The relevant input and output files are then opened and the cipher is used to encrypt the data, and write it to the output file. 
For decryption, the program first base64 decodes the key and IV (which the user give the program) and uses this, along with the cipher algorithm, to create and initialse the cipher. The relevant input and output files are then opened and the cipher is used to decrypt the data, and write it to the output file. 

Design Decisions
- Ensure correct arguments are entered
I used this design decision to ensure the user enters the correct number of arguments to reduce the amount of possible errors that could occur. The code won't and shouldn't work unless all the arguments are given hence, by checking arguemnts, this means no code is run until the correct arguments are entered.

- Display information error messages which don't give away important information
I used this design design to ensure that if an error occurs, the user can determine why the error occured. However, the error messages which are shown won't reveal important information. This is important as it means there aren't any information leaks, making the code more secure.

- Using CipherInputStream for encryption and decryption
This has been used as these cipher streams are secure and allows for easy encryption and decryption of information. 

- Generate a random IV and key when encrypting using SecureRandom
The IV and key need to be randomly generated to ensure the code is more secure and an attacker is less likely to guess them. Due to this, I have used SecureRandom as it is a "cryptographically strong random number generator" as per https://www.baeldung.com/java-secure-random. This ensures the randomly generated IV and key are quite strong and random, making them more secure. 

- Only display the randomly generated password and IV if the encryption is successful 
I chosen this design decision as the generated password and IV only need to be displayed if the encyrption was successful, otherwise they are useless. 

Why the design is secure:
My design is secure because I randomly generate the key and IV values. I also ensure the error messages displayed don't reveal important information. Furthermore, CipherInputStream is used as it represents a secure cipher stream. 