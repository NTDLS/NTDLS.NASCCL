# NTDLS.NASCCL

NetowkrDLS Algorithmic Symmetric Cipher Cryptography Library. Original C++ library ported to C#

*Simple string encryption example:*

```
	var nasccl = new NASCCLStream("ThisIsTheP@$$w0Rd!");
	var cipherBytes = nasccl.Cipher("This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!");
	var decipherBytes = nasccl.Cipher(cipherBytes);
	string decipheredText = Encoding.UTF8.GetString(decipherBytes);
```
