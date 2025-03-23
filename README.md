# NTDLS.Permafrost

📦 Be sure to check out the NuGet package: https://www.nuget.org/packages/NTDLS.Permafrost

Permafrost encryption library, derived from NASCCL. The NetworkDLS Algorithmic Symmetric Cipher Cryptography Library.

## Simple string encryption example:

```
using var permafrost = new PermafrostCipher("ThisIsTheP@$$w0Rd!", PermafrostMode.AutoReset);
var cipherBytes = permafrost.Cipher("This is some text that I would like to keep safe if that is ok with you? Oh, it is? Good!");
var decipherBytes = permafrost.Cipher(cipherBytes);
string decipheredText = Encoding.UTF8.GetString(decipherBytes);
```

## Streaming example with chaining.
```
public static void EncryptAndCompressFile(string inputPath, string outputPath)
{
    byte[] buffer = new byte[8192];

    using var input = File.OpenRead(inputPath);
    using var output = File.Create(outputPath);
    using var permafrost = new PermafrostStream(output, "ThisIsTheP@$$w0Rd!");
    using var gzip = new GZipStream(permafrost, CompressionLevel.SmallestSize);

    int bytesRead;
    while ((bytesRead = input.Read(buffer, 0, buffer.Length)) > 0)
    {
        gzip.Write(buffer, 0, bytesRead);
    }
}

public static void DecryptAndDecompressFile(string inputPath, string outputPath)
{
    byte[] buffer = new byte[8192];

    using var input = File.OpenRead(inputPath);
    using var permafrost = new PermafrostStream(input, "ThisIsTheP@$$w0Rd!");
    using var gzip = new GZipStream(permafrost, CompressionMode.Decompress);
    using var output = File.Create(outputPath);

    int bytesRead;
    while ((bytesRead = gzip.Read(buffer, 0, buffer.Length)) > 0)
    {
        output.Write(buffer, 0, bytesRead);
    }
}
```

## Visulation of 1MB NULL values.
![TestOutput txt](https://github.com/user-attachments/assets/92b152c0-0cb5-4ecd-bf24-a59c431351f6)
