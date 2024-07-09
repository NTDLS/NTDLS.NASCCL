# NTDLS.NASCCL

📦 Be sure to check out the NuGet package: https://www.nuget.org/packages/NTDLS.NASCCL

NetworkDLS Algorithmic Symmetric Cipher Cryptography Library. Original C++ library ported to C#

*Simple string encryption example:*

```
	var cryptoStream = new CryptoStream("ThisIsTheP@$$w0Rd!");
	var cipherBytes = cryptoStream.Cipher("This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!");
	var decipherBytes = cryptoStream.Cipher(cipherBytes);
	string decipheredText = Encoding.UTF8.GetString(decipherBytes);
```
