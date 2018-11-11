***************       HIDE AND SEEK GUIDE       ***************
            Simple encryption/decryption application
            
  Write in Command prompt the following line :                
  HideAndSeek.cs fileInput /k:key [/o:fileOutput] [/d] [/v] [/?]

  Rules: 
  HideAndSeek.cs is the name of the program. 
  fileInput - file to encrypt/decrypt.      
  /k:key - the key for encryption. Has to be a hexadecimal      
  [/o:fileOutput]- file for output. If not provided, another one
  will be generated. The following rule applies for the new files: 
    File.txt encrypt -> File.txt.enc 
    File.txt.enc decrypt -> File.txt 
    File.enc decrypt -> File.enc.dec 
    File.txt decrypt -> File.txt.dec 

  [/d] -> decryption. If not given -> encryption                
  [/v] -> adds a CRC at the end of the encrypted file and the 
  length of the original file. Useful   
  to check the validity of the encryption before it is decrypted.
  
  Cannot be used in the same time as [/d] ");
      
     [/?] Informations ");
*****************************************************************
