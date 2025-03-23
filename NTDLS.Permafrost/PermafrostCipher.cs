///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Copyright © NetworkDLS 2002, All rights reserved
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF 
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A 
// PARTICULAR PURPOSE.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System;
using System.Security.Cryptography;
using System.Text;

namespace NTDLS.Permafrost
{
    /// <summary>
    /// NASCCL/Permafrost (NetworkDLS Algorithmic Symmetric Cipher Cryptography Library).
    /// </summary>
    public class PermafrostCipher : IDisposable
    {
        /// <summary>
        /// Whether to use AutoReset mode or Continuous mode.
        /// In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode,
        /// the encryption is expected to be continuous and each call to Cipher() depends on the call before it.
        /// </summary>
        public PermafrostMode Mode { get; set; }

        private readonly byte[] _defaultSeed = Encoding.UTF8.GetBytes("BdlgylbjsAs7owqsRdemY8TvHuuWD16D\r\nCGXat20B8IJyD9kQYcY5Fz0Qd3fueSrS\r\nQhakrrL5yTZ7bwvC4qbK3VSpyonZDrQN\r\nlnFpSoBsVpjfVpiARrbPyJGN0OewXtuk\r\n3BZT7wmXBJuCX42vnV99xxD3z37HngRY\r\nAeeoVKst1RqJdCiZ1VKM9Si14OXWFiJv\r\nQiPikSjwJ5UiXElLsYdw2sHZHH9EJNZH\r\nzPelVL3bxcMSCeNyctFzmUkIIiv6eylB\r\nlKgWbXbpLjMYc6UIIbHhP36S4TdTfcXv\r\no0LpxKFoJtUMYWTjyhMI8y5PYXojo2p3");

        private bool _disposed;
        private ulong _saltHashCounter = 0;
        private byte[]? _keyBuffer = null;
        private byte[]? _originalKeyBuffer = null;

        private int _suppliedKeySize;
        private int _suppliedKeyIndex;
        private int _saltBoxIndex;

        private byte[,]? _boxes = null;
        private byte[,]? _keySalt = null;
        private byte[,]? _OriginalKeySalt = null;

        /// <summary>
        /// The default number of salt boxes to generate.
        /// </summary>
        public readonly int DefaultSaltBoxCount = 64;
        /// <summary>
        /// The minimum number of salt boxes to generate.
        /// </summary>
        public readonly int MinimumSaltBoxCount = 16;
        /// <summary>
        /// The maximum number of salt boxes to generate.
        /// </summary>
        public readonly int MaximumSaltBoxCount = 10 * 1024;

        /// <summary>
        /// The number of salt boxes generated.
        /// </summary>
        public int SaltBoxCount { get; private set; } = 0;
        private const int SaltBoxValueCount = 256;

        /// <summary>
        /// Clears out the variables used for encryption.
        /// </summary>
        ~PermafrostCipher()
        {
            Destroy();
        }

        /// <summary>
        /// Clears out the variables used for encryption.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                Destroy();
                _disposed = true;
            }
        }

        #region Constructors.

        /// <summary>
        /// Initializes a new instance of Permafrost without a key.
        /// Initialize() must be called before using.
        /// </summary>
        public PermafrostCipher() { }

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public PermafrostCipher(byte[] key)
            => Initialize(_defaultSeed, DefaultSaltBoxCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode)
            => Initialize(_defaultSeed, DefaultSaltBoxCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public PermafrostCipher(string key)
            => Initialize(_defaultSeed, DefaultSaltBoxCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public PermafrostCipher(string key, PermafrostMode mode)
            => Initialize(_defaultSeed, DefaultSaltBoxCount, Encoding.UTF8.GetBytes(key), mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        public PermafrostCipher(byte[] key, byte[] seed)
            => Initialize(seed, DefaultSaltBoxCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode, byte[] seed)
            => Initialize(seed, DefaultSaltBoxCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        public PermafrostCipher(string key, byte[] seed)
            => Initialize(seed, DefaultSaltBoxCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        public PermafrostCipher(string key, PermafrostMode mode, byte[] seed)
            => Initialize(seed, DefaultSaltBoxCount, Encoding.UTF8.GetBytes(key), mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(byte[] key, int saltBoxCount)
            => Initialize(_defaultSeed, saltBoxCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode, int saltBoxCount)
            => Initialize(_defaultSeed, saltBoxCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public PermafrostCipher(string key, int saltBoxCount)
            => Initialize(_defaultSeed, saltBoxCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(string key, PermafrostMode mode, int saltBoxCount)
            => Initialize(_defaultSeed, saltBoxCount, Encoding.UTF8.GetBytes(key), mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(byte[] key, byte[] seed, int saltBoxCount)
            => Initialize(seed, saltBoxCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode, byte[] seed, int saltBoxCount)
            => Initialize(seed, saltBoxCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(string key, byte[] seed, int saltBoxCount)
            => Initialize(seed, saltBoxCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">byte array used to generate s-boxes</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        public PermafrostCipher(string key, PermafrostMode mode, byte[] seed, int saltBoxCount)
            => Initialize(seed, saltBoxCount, Encoding.UTF8.GetBytes(key), mode);

        #endregion

        /// <summary>
        /// Fills a single salt-box with PRNG values based on the given seed.
        /// </summary>
        private void FillSaltBox(byte[] seed, byte[] buffer)
        {
            using var shaHMAC256 = new HMACSHA256(seed);

            int offset = 0;

            while (offset < buffer.Length)
            {
                var counterBytes = BitConverter.GetBytes(_saltHashCounter++);

                if (BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes); //For consistent output across platforms

                byte[] hash = shaHMAC256.ComputeHash(counterBytes);
                int toCopy = Math.Min(hash.Length, buffer.Length - offset);
                Array.Copy(hash, 0, buffer, offset, toCopy);
                offset += toCopy;
            }
        }

        private byte[,] GenerateSaltBoxes(byte[] seed, int saltBoxCount)
        {
            if (_saltHashCounter != 0)
            {
                throw new InvalidOperationException("Permafrost has already been initialized.");
            }
            if (SaltBoxCount != 0)
            {
                throw new InvalidOperationException("Permafrost has already been initialized.");
            }

            if (saltBoxCount < MinimumSaltBoxCount || saltBoxCount > MaximumSaltBoxCount)
            {
                throw new ArgumentOutOfRangeException(nameof(saltBoxCount), $"The number of salt boxes must be between {MinimumSaltBoxCount} and {MaximumSaltBoxCount}.");
            }

            SaltBoxCount = saltBoxCount;

            byte[,] boxes = new byte[SaltBoxCount, SaltBoxValueCount];

            for (int i = 0; i < seed.Length; i++)
            {
                seed[i] = (byte)(seed[i] ^ (saltBoxCount % 255));
            }

            //Fill the Boxes array
            for (int box = 0; box < SaltBoxCount; box++)
            {
                byte[] saltBox = new byte[SaltBoxValueCount];
                FillSaltBox(seed, saltBox);

                for (int value = 0; value < SaltBoxValueCount; value++)
                {
                    boxes[box, value] = saltBox[value];
                }
            }

            return boxes;
        }

        /// <summary>
        /// Generates key salt values from a byte array.
        /// </summary>
        /// <param name="keyBuffer">The bytes to use as the encryption/decryption key.</param>
        public byte[,] GenerateKeySalt(byte[] keyBuffer)
        {
            if (_boxes == null)
            {
                throw new InvalidOperationException("Permafrost has not been initialized.");
            }

            byte saltValue = 0;
            int suppliedKeyIndex = 0;

            var keySalt = new byte[SaltBoxCount, SaltBoxValueCount];

            for (int box = 0; box < SaltBoxCount; box++)
            {
                for (int val = 0; val < SaltBoxValueCount; val++)
                {
                    if (suppliedKeyIndex == keyBuffer.Length)
                    {
                        suppliedKeyIndex = 0;
                    }

                    saltValue = (byte)((keyBuffer[suppliedKeyIndex] * ((val + 1) * (box + 1)))
                        ^ _boxes[box, (keyBuffer[suppliedKeyIndex] ^ saltValue) % 255]);

                    keySalt[box, val] = saltValue;

                    suppliedKeyIndex++;
                }
            }

            return keySalt;
        }

        /// <summary>
        /// Generates key salt values from a UTF8 string.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public byte[,] GenerateKeySalt(string key)
            => GenerateKeySalt(Encoding.UTF8.GetBytes(key));

        /// <summary>
        /// Initializes all internal variables using the suppled key and defined mode.
        /// </summary>
        /// <param name="seed">byte array used to generate s-boxes.</param>
        /// <param name="saltBoxCount">The number of salt boxes to generate.</param>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public void Initialize(byte[] seed, int saltBoxCount, byte[] key, PermafrostMode mode)
        {
            _boxes = GenerateSaltBoxes(seed, saltBoxCount);

            _suppliedKeyIndex = (key.Length - 1);
            _suppliedKeySize = key.Length;
            _saltBoxIndex = 0;

            Mode = PermafrostMode.Continuous;

            _keyBuffer = key.Copy();
            _originalKeyBuffer = _keyBuffer.Copy();

            _keySalt = GenerateKeySalt(_keyBuffer);
            _OriginalKeySalt = _keySalt.Copy();

            Mode = mode;

            ResetStream();
        }

        /// <summary>
        /// Initializes all internal variables using the suppled key and defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public void Initialize(byte[] key, PermafrostMode mode)
            => Initialize(_defaultSeed, DefaultSaltBoxCount, key, mode);

        /// <summary>
        /// Resets the continuous stream so that the next call to Cipher() does not depend on the previous calls.
        /// </summary>
        public void ResetStream()
        {
            _suppliedKeyIndex = (_suppliedKeySize - 1);
            _saltBoxIndex = 0;

            if (_keyBuffer == null || _originalKeyBuffer == null || _OriginalKeySalt == null || _keySalt == null)
            {
                throw new InvalidOperationException("Permafrost has not been initialized.");
            }

            Array.Copy(_OriginalKeySalt, _keySalt, _OriginalKeySalt.Length);
            Array.Copy(_originalKeyBuffer, _keyBuffer, _originalKeyBuffer.Length);
        }

        /// <summary>
        /// Clears out the variables used for encryption.
        /// This call is not required, and resources are not leaked if not called, this is a security measure to counter memory sniffing.
        /// </summary>
        public void Destroy()
        {
            if (_disposed) return;

            _suppliedKeySize = 0;
            _suppliedKeyIndex = 0;
            _saltBoxIndex = 0;
            Mode = PermafrostMode.Continuous;

            _keyBuffer?.Sanitize();
            _originalKeyBuffer?.Sanitize();
            _OriginalKeySalt?.Sanitize();
            _keySalt?.Sanitize();
        }

        /// <summary>
        /// Encrypts a UTF8 string and returns the encrypted bytes.
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        public byte[] EncryptString(string source)
            => Cipher(Encoding.UTF8.GetBytes(source));

        /// <summary>
        /// Decrypts a byte array and returns the decrypted string.
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        public string DecryptString(byte[] source)
            => Encoding.UTF8.GetString(Cipher(source));

        /// <summary>
        /// Encrypts or decrypts a byte array and returns the reversed bytes.
        /// </summary>
        /// <param name="source">The bytes to encrypt or decrypt.</param>
        /// <returns>The reversed encrypted or decrypted bytes.</returns>
        public byte[] Cipher(byte[] source)
        {
            var target = new byte[source.Length];
            Cipher(source, target);
            return target;
        }

        /// <summary>
        /// Encrypts or decrypts the referenced byte array.
        /// </summary>
        /// <param name="sourceAndTarget">The byte array to encrypt or decrypt.</param>
        public void CipherInPlace(byte[] sourceAndTarget)
            => Cipher(sourceAndTarget, sourceAndTarget);

        /// <summary>
        /// Encrypts or decrypts the referenced byte array.
        /// </summary>
        /// <param name="sourceAndTarget">The byte array to encrypt or decrypt.</param>
        /// <param name="length">Length of the source buffer.</param>
        public void CipherInPlace(byte[] sourceAndTarget, int length)
            => Cipher(sourceAndTarget, 0, length, sourceAndTarget);

        /// <summary>
        /// Encrypts or decrypts the source byte array and returns the reversed bytes via target.
        /// </summary>
        /// <param name="source">The bytes to encrypt or decrypt.</param>
        /// <param name="target">The reversed encrypted or decrypted bytes.</param>
        public void Cipher(byte[] source, byte[] target)
            => Cipher(source, 0, source.Length, target);

        /// <summary>
        /// Encrypts or decrypts the source byte array and returns the reversed bytes via target.
        /// </summary>
        /// <param name="source">The bytes to encrypt or decrypt.</param>
        /// <param name="startIndex">The starting index in the buffer to begin the cipher operation.</param>
        /// <param name="sourceLength">The length of the source buffer for cipher operations.</param>
        /// <param name="target">The reversed encrypted or decrypted bytes.</param>
        public void Cipher(byte[] source, int startIndex, int sourceLength, byte[] target)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(Permafrost));
            }

            if (_keySalt == null || _keyBuffer == null)
            {
                throw new InvalidOperationException("Permafrost has not been initialized.");
            }

            if (SaltBoxCount == 0)
            {
                throw new InvalidOperationException("Permafrost has not been initialized.");
            }

            if (Mode == PermafrostMode.AutoReset)
            {
                ResetStream();
            }
            else if (Mode == PermafrostMode.Undefined)
            {
                throw new InvalidOperationException("Permafrost mode has not been defined.");
            }

            for (uint index = (uint)startIndex; index < sourceLength; index++)
            {
                if (_suppliedKeyIndex == -1)
                {
                    _suppliedKeyIndex = (_suppliedKeySize - 1);
                }

                if (_saltBoxIndex == SaltBoxCount)
                {
                    _saltBoxIndex = 0;
                }

                var swapBuffer = _keySalt[_saltBoxIndex, _keyBuffer[_suppliedKeyIndex]];
                _keySalt[_saltBoxIndex, (_keyBuffer)[_suppliedKeyIndex]] = _keyBuffer[_suppliedKeyIndex];
                _keyBuffer[_suppliedKeyIndex] = (byte)swapBuffer;

                target[index] = (byte)(source[index] ^ _keySalt[_saltBoxIndex, _keyBuffer[_suppliedKeyIndex]]);

                _suppliedKeyIndex--;
                _saltBoxIndex++;
            }
        }
    }
}
