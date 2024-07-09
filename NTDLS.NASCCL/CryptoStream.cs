///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Copyright © NetworkDLS 2002, All rights reserved
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF 
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A 
// PARTICULAR PURPOSE.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System;
using System.Text;

namespace NTDLS.NASCCL
{
    /// <summary>
    /// NetworkDLS Algorithmic Symmetric Cipher Cryptography Library for .net.
    /// </summary>
    public class CryptoStream
    {
        private bool _useBlockMode;

        private byte[] _keyBuffer;
        private byte[] _originalKeyBuffer;

        private int _suppliedKeySize;
        private int _suppliedKeyIndex;
        private int _saltBoxIndex;

        private byte[,] _keySalt;
        private byte[,] _OriginalKeySalt;

        /// <summary>
        /// Generates key salt values from a UTF8 string.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public static byte[,] GenerateKeySalt(string key)
            => KeyExpansion.GenerateKeySalt(Encoding.UTF8.GetBytes(key));

        /// <summary>
        /// Generates key salt values from a byte array.
        /// </summary>
        /// <param name="keyBuffer">The bytes to use as the encryption/decryption key.</param>
        public static byte[,] GenerateKeySalt(byte[] keyBuffer)
            => KeyExpansion.GenerateKeySalt(keyBuffer);

        /// <summary>
        /// Initializes a new instance of the NASCCL stream without a key. Initialize() must be called before using.
        /// </summary>
        public CryptoStream() { }

        /// <summary>
        /// Initializes a new instance of the NASCCL stream using a key in auto-reset mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public CryptoStream(byte[] key)
            => Initialize(key, true);

        /// <summary>
        /// Initializes a new instance of the NASCCL stream using a key and a defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="useBlockMode">Whether to use block mode or stream mode. In block mode the order of encryption and decryption do not matter, but in stream mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public CryptoStream(byte[] key, bool useBlockMode)
            => Initialize(key, useBlockMode);

        /// <summary>
        /// Initializes a new instance of the NASCCL stream using a key in block mode.
        /// </summary>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        public CryptoStream(string key)
            => Initialize(Encoding.UTF8.GetBytes(key), true);

        /// <summary>
        /// Initializes a new instance of the NASCCL stream using a key and a defined mode.
        /// </summary>
        /// <param name="key">The string to use as the encryption/decryption key.</param>
        /// <param name="useBlockMode">Whether to use block mode or stream mode. In block mode the order of encryption and decryption do not matter, but in stream mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public CryptoStream(string key, bool useBlockMode)
            => Initialize(Encoding.UTF8.GetBytes(key), useBlockMode);

        /// <summary>
        /// Initializes all internal variables using the suppled key and defined mode.
        /// </summary>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="useBlockMode">Whether to use block mode or stream mode. In block mode the order of encryption and decryption do not matter, but in stream mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        public void Initialize(byte[] key, bool useBlockMode)
        {
            _suppliedKeyIndex = (key.Length - 1);
            _suppliedKeySize = key.Length;
            _saltBoxIndex = 0;

            _useBlockMode = false;

            _keyBuffer = key.Copy();
            _originalKeyBuffer = _keyBuffer.Copy();

            _keySalt = KeyExpansion.GenerateKeySalt(_keyBuffer);
            _OriginalKeySalt = _keySalt.Copy();

            _useBlockMode = useBlockMode;

            ResetStream();
        }

        /// <summary>
        /// Resets the stream so that the next call to Cipher() does not depend on the previous calls.
        /// </summary>
        public void ResetStream()
        {
            _suppliedKeyIndex = (_suppliedKeySize - 1);
            _saltBoxIndex = 0;

            Array.Copy(_OriginalKeySalt, _keySalt, _OriginalKeySalt.Length);
            Array.Copy(_originalKeyBuffer, _keyBuffer, _originalKeyBuffer.Length);
        }

        /// <summary>
        /// Clears out the variables used for encryption.
        /// This call is not required, and resources are not leaked if not called, this is a security measure to counter memory sniffing.
        /// </summary>
        public void Destroy()
        {
            _suppliedKeySize = 0;
            _suppliedKeyIndex = 0;
            _saltBoxIndex = 0;
            _useBlockMode = false;

            _keyBuffer.Sanitize();
            _originalKeyBuffer.Sanitize();
            _OriginalKeySalt.Sanitize();
            _keySalt.Sanitize();
        }

        /// <summary>
        /// Encrypts a UTF8 string and returns the encrypted bytes.
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        public byte[] Cipher(string source)
            => Cipher(Encoding.UTF8.GetBytes(source));

        /// <summary>
        /// Encrypts or decrypts a byte array and returns the reversed bytes.
        /// </summary>
        /// <param name="source">The bytes to encrypt or decrypt.</param>
        /// <returns>The reversed encrypted or decrypted bytes.</returns>
        public byte[] Cipher(byte[] source)
        {
            var target = new byte[source.Length];
            Cipher(source, ref target);
            return target;
        }

        /// <summary>
        /// Encrypts or decrypts the referenced byte array.
        /// </summary>
        /// <param name="sourceAndTarget">The byte array to encrypt or decrypt.</param>
        public void Cipher(ref byte[] sourceAndTarget)
            => Cipher(sourceAndTarget, ref sourceAndTarget);

        /// <summary>
        /// Encrypts or decrypts the source byte array and returns the reversed bytes via target.
        /// </summary>
        /// <param name="source">The bytes to encrypt or decrypt.</param>
        /// <param name="target">The reversed encrypted or decrypted bytes.</param>
        public void Cipher(byte[] source, ref byte[] target)
        {
            if (_useBlockMode)
            {
                ResetStream();
            }

            for (uint index = 0; index < source.Length; index++)
            {
                if (_suppliedKeyIndex == -1)
                {
                    _suppliedKeyIndex = (_suppliedKeySize - 1);
                }

                if (_saltBoxIndex == KeyExpansion.BoxCount)
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
