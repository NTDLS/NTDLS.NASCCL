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
    public class NASCCLStream
    {
        private bool _autoReset;

        private byte[] _keyBuffer;
        private byte[] _originalKeyBuffer;

        private int _suppliedKeySize;
        private int _suppliedKeyIndex;
        private int _saltBoxIndex;

        private ushort[,] _keySalt;
        private ushort[,] _OriginalKeySalt;

        public NASCCLStream() { }

        public NASCCLStream(byte[] key) => Initialize(key, true);

        public NASCCLStream(byte[] key, bool autoReset) => Initialize(key, autoReset);

        public NASCCLStream(string key) => Initialize(Encoding.UTF8.GetBytes(key), true);

        public NASCCLStream(string sKey, bool autoReset) => Initialize(Encoding.UTF8.GetBytes(sKey), autoReset);

        public void Initialize(byte[] key, bool autoReset)
        {
            _suppliedKeyIndex = (key.Length - 1);
            _suppliedKeySize = key.Length;
            _saltBoxIndex = 0;

            _autoReset = false;

            _keyBuffer = Extensions.Clone(key);
            _originalKeyBuffer = Extensions.Clone(_keyBuffer);

            _keySalt = HardcodedSaltValues.BuildKeyBoxes(_keyBuffer);
            _OriginalKeySalt = Extensions.Clone(_keySalt);

            _autoReset = autoReset;

            ResetStream();
        }

        public void ResetStream()
        {
            _suppliedKeyIndex = (_suppliedKeySize - 1);
            _saltBoxIndex = 0;

            Array.Copy(_OriginalKeySalt, _keySalt, _OriginalKeySalt.Length);
            Array.Copy(_originalKeyBuffer, _keyBuffer, _originalKeyBuffer.Length);
        }

        public void Destroy()
        {
            _suppliedKeySize = 0;
            _suppliedKeyIndex = 0;
            _saltBoxIndex = 0;
            _autoReset = false;

            _keyBuffer.ZeroOut();
            _originalKeyBuffer.ZeroOut();
            _OriginalKeySalt.ZeroOut();
            _keySalt.ZeroOut();
        }

        public byte[] Cipher(string source)
        {
            return Cipher(Encoding.UTF8.GetBytes(source));
        }

        public byte[] Cipher(byte[] source)
        {
            byte[] target = new byte[source.Length];

            if (_autoReset)
            {
                ResetStream();
            }

            for (uint index = 0; index < source.Length; index++)
            {
                if (_suppliedKeyIndex == -1)
                {
                    _suppliedKeyIndex = (_suppliedKeySize - 1);
                }

                if (_saltBoxIndex == HardcodedSaltValues.BoxCount)
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

            return target;
        }
    }
}
