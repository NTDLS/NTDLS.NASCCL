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

        private readonly byte[] _defaultSeed = Encoding.UTF8.GetBytes("BdlgylbjsAs7owqsRdemY8TvHuuWD16DCGXat20B8IJyD9kQYcY5Fz0Qd3fueSrSQhakrrL5yTZ7bwvC4qbK3VSpyonZDrQNlnFpSoBsVpjfVpiARrbPyJGN0OewXtuk");

        private bool _disposed;
        private ulong _KeyScheduleGenCounter = 0;
        private byte[]? _keyBuffer = null;
        private byte[]? _originalKeyBuffer = null;

        private int _suppliedKeySize;
        private int _suppliedKeyIndex;
        private int _keyScheduleIndex;

        private byte[,]? _keySchedule = null;

        /// <summary>
        /// The default number of key schedules to generate.
        /// </summary>
        public readonly int DefaultKeyScheduleCount = 64;
        /// <summary>
        /// The minimum number of key schedules to generate.
        /// </summary>
        public readonly int MinimumKeyScheduleCount = 1;
        /// <summary>
        /// The maximum number of key schedule to generate.
        /// </summary>
        public readonly int MaximumKeyScheduleCount = 10 * 1024;

        /// <summary>
        /// The number of key schedules generated.
        /// </summary>
        public int KeyScheduleCount { get; private set; } = 0;
        private const int keyScheduleValueCount = 256;

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
            => Initialize(_defaultSeed, DefaultKeyScheduleCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode)
            => Initialize(_defaultSeed, DefaultKeyScheduleCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public PermafrostCipher(string key)
            => Initialize(_defaultSeed, DefaultKeyScheduleCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public PermafrostCipher(string key, PermafrostMode mode)
            => Initialize(_defaultSeed, DefaultKeyScheduleCount, Encoding.UTF8.GetBytes(key), mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        public PermafrostCipher(byte[] key, byte[] seed)
            => Initialize(seed, DefaultKeyScheduleCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode, byte[] seed)
            => Initialize(seed, DefaultKeyScheduleCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        public PermafrostCipher(string key, byte[] seed)
            => Initialize(seed, DefaultKeyScheduleCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        public PermafrostCipher(string key, PermafrostMode mode, byte[] seed)
            => Initialize(seed, DefaultKeyScheduleCount, Encoding.UTF8.GetBytes(key), mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(byte[] key, int keyScheduleCount)
            => Initialize(_defaultSeed, keyScheduleCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode, int keyScheduleCount)
            => Initialize(_defaultSeed, keyScheduleCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public PermafrostCipher(string key, int keyScheduleCount)
            => Initialize(_defaultSeed, keyScheduleCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(string key, PermafrostMode mode, int keyScheduleCount)
            => Initialize(_defaultSeed, keyScheduleCount, Encoding.UTF8.GetBytes(key), mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(byte[] key, byte[] seed, int keyScheduleCount)
            => Initialize(seed, keyScheduleCount, key, PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(byte[] key, PermafrostMode mode, byte[] seed, int keyScheduleCount)
            => Initialize(seed, keyScheduleCount, key, mode);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key in Continuous mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(string key, byte[] seed, int keyScheduleCount)
            => Initialize(seed, keyScheduleCount, Encoding.UTF8.GetBytes(key), PermafrostMode.Continuous);

        /// <summary>
        /// Initializes a new instance of Permafrost using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">Byte array used to generate key schedules.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        public PermafrostCipher(string key, PermafrostMode mode, byte[] seed, int keyScheduleCount)
            => Initialize(seed, keyScheduleCount, Encoding.UTF8.GetBytes(key), mode);

        #endregion

        /// <summary>
        /// Fills a single key schedule with PRNG values based on the given seed.
        /// </summary>
        private byte[] GenerateSingleKeySchedule(byte[] seed, int length)
        {
            byte[] buffer = new byte[length];

            using var shaHMAC256 = new HMACSHA256(seed);

            int offset = 0;

            while (offset < length)
            {
                var counterBytes = BitConverter.GetBytes(_KeyScheduleGenCounter++);

                if (BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes); //For consistent output across platforms

                byte[] hash = shaHMAC256.ComputeHash(counterBytes);
                int toCopy = Math.Min(hash.Length, buffer.Length - offset);
                Array.Copy(hash, 0, buffer, offset, toCopy);
                offset += toCopy;
            }

            return buffer;
        }

        private void PopulateKeySchedule(byte[] seed, int keyScheduleCount)
        {
            if (_KeyScheduleGenCounter != 0)
            {
                throw new InvalidOperationException("Permafrost has already been initialized.");
            }
            if (KeyScheduleCount != 0)
            {
                throw new InvalidOperationException("Permafrost has already been initialized.");
            }

            if (keyScheduleCount < MinimumKeyScheduleCount || keyScheduleCount > MaximumKeyScheduleCount)
            {
                throw new ArgumentOutOfRangeException(nameof(keyScheduleCount), $"The number of key schedules must be between {MinimumKeyScheduleCount} and {MaximumKeyScheduleCount}.");
            }

            KeyScheduleCount = keyScheduleCount;

            _keySchedule = new byte[KeyScheduleCount, keyScheduleValueCount];

            for (int i = 0; i < seed.Length; i++)
            {
                seed[i] = (byte)(seed[i] ^ (keyScheduleCount % 255));
            }

            //Fill the key schedule with PRNG values based on the seed.
            for (int schedule = 0; schedule < KeyScheduleCount; schedule++)
            {
                byte[] keySchedule = GenerateSingleKeySchedule(seed, keyScheduleValueCount);

                for (int valueIndex = 0; valueIndex < keyScheduleValueCount; valueIndex++)
                {
                    _keySchedule[schedule, valueIndex] = keySchedule[valueIndex];
                }
            }
        }

        /// <summary>
        /// Initializes all internal variables using the suppled key and defined mode.
        /// </summary>
        /// <param name="seed">Byte array used to generate key schedules..</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate.</param>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public void Initialize(byte[] seed, int keyScheduleCount, byte[] key, PermafrostMode mode)
        {
            PopulateKeySchedule(seed, keyScheduleCount);

            _suppliedKeyIndex = (key.Length - 1);
            _suppliedKeySize = key.Length;
            _keyScheduleIndex = 0;

            Mode = PermafrostMode.Continuous;

            _keyBuffer = key.Copy();
            _originalKeyBuffer = _keyBuffer.Copy();

            Mode = mode;

            ResetStream();
        }

        /// <summary>
        /// Initializes all internal variables using the suppled key and defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public void Initialize(byte[] key, PermafrostMode mode)
            => Initialize(_defaultSeed, DefaultKeyScheduleCount, key, mode);

        /// <summary>
        /// Resets the continuous stream so that the next call to Cipher() does not depend on the previous calls.
        /// </summary>
        public void ResetStream()
        {
            _suppliedKeyIndex = (_suppliedKeySize - 1);
            _keyScheduleIndex = 0;

            if (_keyBuffer == null || _originalKeyBuffer == null || _keySchedule == null)
            {
                throw new InvalidOperationException("Permafrost has not been initialized.");
            }

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
            _keyScheduleIndex = 0;
            Mode = PermafrostMode.Continuous;

            _keyBuffer?.Sanitize();
            _originalKeyBuffer?.Sanitize();
            _keySchedule?.Sanitize();
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

            if (_keySchedule == null || _keyBuffer == null)
            {
                throw new InvalidOperationException("Permafrost has not been initialized.");
            }

            if (KeyScheduleCount == 0)
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

                if (_keyScheduleIndex == KeyScheduleCount)
                {
                    _keyScheduleIndex = 0;
                }

                target[index] = (byte)(source[index] ^ _keySchedule[_keyScheduleIndex, _keyBuffer[_suppliedKeyIndex]]);

                //Mutate the key buffer.
                _keyBuffer[_suppliedKeyIndex] ^= (byte)((_suppliedKeyIndex + 11 + _keyScheduleIndex) % 256);

                _suppliedKeyIndex--;
                _keyScheduleIndex++;
            }
        }
    }
}
