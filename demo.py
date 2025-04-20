import bcrypt 
  
# example password 
password = 'Abcd!@#$1234'
  
# converting password to array of bytes 
bytes = password.encode('utf-8') 
  
# generating the salt 
salt = bcrypt.gensalt() 
  
# Hashing the password 
hash = bcrypt.hashpw(bytes, salt) 
  
# Taking user entered password  
userPassword =  'Abcd!@#$1234'
  
# encoding user password 
userBytes = userPassword.encode('utf-8') 
  
# checking password 
result = bcrypt.checkpw(userBytes, hash) 

print(password)
print(bytes)
print(userBytes)