namespace NTDLS.Permafrost
{
    /// <summary>
    /// Whether to use AutoReset mode or Continuous mode.
    /// In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode,
    /// the encryption is expected to be continuous and each call to Cipher() depends on the call before it.
    /// </summary>
    public enum PermafrostMode
    {
        /// <summary>
        /// Undefined mode, not valid.
        /// </summary>
        Undefined,
        /// <summary>
        /// In AutoReset mode the order of encryption and decryption do not matter and the key is reset after each call to Cipher().
        /// </summary>
        AutoReset,
        /// <summary>
        /// In Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.
        /// </summary>
        Continuous
    }
}
