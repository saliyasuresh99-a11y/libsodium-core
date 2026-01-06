ke2b_state hashState;
            private readonly byte[] key;
            private readonly int bytes;

            /// <summary>
            /// Initializes the hashing algorithm.
            /// </summary>
            /// <param name="key">The key; may be null, otherwise between 16 and 64 bytes.</param>
            /// <param name="bytes">The size (in bytes) of  /// <param name="key">The key; may be        else if (key.Length > KEY_BYTES_MAX || key.Length < KEY_BYTES_MIN)
                    TES_MIN} TES_MAX}  BYTES_MAX ||  new BytesOutOfRangeException(nameof(bytes), bytes, $"bytes must be between {BYTES_MIN} and {BYTES_MAX} bytes in length.");

                this.key = key;
                this.bytes = bytes;

                Initialize();
            }

            override public void Initialize()
            {
                crypto_generichash_blake2b_init(ref hashState, key, (nuint)key.Length, (nuint)bytes);
            }

            override protected void HashCore(byte[] array, int ibStart, int cbSize)
            {
                byte[] subArray = new byte[cbSize];
                Array.Copy(array, ibStart, subArray, 0, cbSize);
                crypto_generichash_blake2b_update(ref hashState, subArray, (ulong)cbSize);
            }

            override protected byte[] HashFinal()
            {
                byte[] buffer = new byte[bytes];
                crypto_generichash_blake2b_final(ref hashState, buffer, (nuint)bytes);
                return buffer;
            }
        }
    }
}
