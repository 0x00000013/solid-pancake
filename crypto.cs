using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg.OpenPgp;
class PGP
{

    public static string PublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

        mQENBFnTaKoBCACoprqKfUmuzAsNbqcDago0GBOMPZOuF/+v+cpHvbjkRAZg7Cv+
        Xjx4GWJzQFow3wvtnml4sJTKsCzS43rHHltfhBQW1HfGzsLMZDap7iO0AHSVf2aq
        xTxf9oU46qgtqy+11Eo5EZhF0+/fCDU/E70BSSbnaOGF5lQTGLLxTlLz69+QciTq
        KgR1/MPNqASiqw3Qszi+Zss0UDu/uoCp+ezjzQst6f3r7LqYC3FlF+sumfdzJHRi
        B9fp99fs99DySui9DoGjQU/pZNi/o4F8jc0V7ZwEzZ812Uno21t2l56FElEoi8XR
        baL3VAc/virsMiXYmnBX436C4Nqi56bcxKcVABEBAAG0JUFsaXJlemEgTW9zYWpq
        YWwgPG1vc2FqamFsQGdtYWlsLmNvbT6JAVQEEwEIAD4CGwMFCwkIBwIGFQgJCgsC
        BBYCAwECHgECF4AWIQTkFTgUQDGxJtDQJ+kQMYcIQt7wFgUCX3OvGQUJDwZH7wAK
        CRAQMYcIQt7wFijdB/9jm5IwAwDlhyGef/e5RzxKqMcVT7BnSRqAPOy4eJAfYrB6
        x/l0oSA9h9lfJjQsJwoIdjNlBIxiaPaeyCUHdNlnJ9QRRWhGwmiZZaMcdSsjMMD3
        +7QJyTQpWmOa+lOo7mLdFOfTVkqRxG7k6JasCELuYq248ngQbAiKNV+WiY2xCRiD
        RE5W+5eOCNiO9ZE7J0wiu6qSIrdgZJxsM+Pq48UWn3pls9nWMGj+bKVeccYLnDnw
        0LzQFSy0OjfgQSOsONQRMAOLKAMy9bsl7RGqhpKLGv21fIIKGuuqaCc7Z1Cm90Qq
        +lO3Q1QpqcuTOh2s1o/pfy6Rk1kTBGpCszUZEKHiuQENBFnTaKoBCADJxizcEAGn
        LhQHCO9uDjjJQPXcQlX1gzeOrKa9xhQpewDDBcbpTTlwIswzZE+drgKmt7v2Me5m
        Rt+NTNZDVM0y7MIZqeVU6SkeinsLjA51QkzgL9Sp1Ch/YYmy0/p2eqb8NHEUx3rA
        n9xf1G2x0ud4LKSuumNKwoz8eS4y4D6faTKuznhOelzHXiDJ0S1EyH3V0QYiQYpu
        MjOu11tDWTKea7A31d7Jy3VtwIdEVFX1Xb/hSCE3VMHk39TA2B5u9/AzlYAe8bHz
        q1HTERlMXlosROcsLD1DG5OJVtAGzg17Q4nGjz7nfBd6YqFuwL87XAaGsFBFnwba
        TL3TvL2uOJjbABEBAAGJATwEGAEIACYCGwwWIQTkFTgUQDGxJtDQJ+kQMYcIQt7w
        FgUCX3OvPAUJDwZIEgAKCRAQMYcIQt7wFtSJB/40M2GyBEtOLlK6pqzQ53Jcp160
        mAznaI2nvEjYXCKH/2ByZnXUIZNM/1apM8hws6nMo73MVciLiIOjMZ1kqxlDhh8A
        ne5S2TNMMXl6VpDygei8tfPL2ddapuiU7+ftWzi3or7y/qbhrDpp/ImBZRVAGwGR
        MRhlpTDWGeLK9OYR+hJ/9rVKp0Mvs5mHHDPMqhDzszdQtW6J7sgHvP1cohP427+R
        sfKengI2RT31gmwMZkzOTwCsWp68TElYgb/YyX8VhtZMCX3oVRxJHt5+Ok+Gs4FS
        fZNATPcO3Y/zWRXNyy5bcE+ndhdoiCvvHOiEBKV/bi9YtGhW2yjT6q7hse9l
        =euoq

        -----END PGP PUBLIC KEY BLOCK-----";

    public PGP() { }

    /**
    * A simple routine that opens a key ring file and loads the first available key suitable for
    * encryption.
    *
    * @param in
    * @return
    * @m_out
    * @
    */
    public static PgpPublicKey ReadPublicKey(Stream inputStream)
    {
        inputStream = PgpUtilities.GetDecoderStream(inputStream);
        PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);
        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //
        //
        // iterate through the key rings.
        //
        foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
        {
            foreach (PgpPublicKey k in kRing.GetPublicKeys())
            {
                if (k.IsEncryptionKey)
                    return k;
            }
        }

        throw new ArgumentException("Can't find encryption key in key ring.");
    }

    /**
    * Search a secret key ring collection for a secret key corresponding to
    * keyId if it exists.
    *
    * @param pgpSec a secret key ring collection.
    * @param keyId keyId we want.
    * @param pass passphrase to decrypt secret key with.
    * @return
    */
    private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
    {
        PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
        if (pgpSecKey == null)
            return null;

        return pgpSecKey.ExtractPrivateKey(pass);
    }

        /**
        * Encrypt the data.
        *
        * @param inputData - byte array to encrypt
        * @param passPhrase - the password returned by "ReadPublicKey"
        * @param withIntegrityCheck - check the data for errors
        * @param armor - protect the data streams
        * @return - encrypted byte array
        */
        public static byte[] Encrypt(byte[] inputData, PgpPublicKey passPhrase, bool withIntegrityCheck, bool armor)
        {
            byte[] processedData = Compress(inputData, PgpLiteralData.Console, CompressionAlgorithmTag.Uncompressed);

            MemoryStream bOut = new MemoryStream();
            Stream output = bOut;

            if (armor)
                output = new ArmoredOutputStream(output);

            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
            encGen.AddMethod(passPhrase);

            Stream encOut = encGen.Open(output, processedData.Length);

            encOut.Write(processedData, 0, processedData.Length);
            encOut.Close();

            if (armor)
                output.Close();

            return bOut.ToArray();
        }

        private static byte[] Compress(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();

            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            Stream pOut = lData.Open(
            cos,                    // the compressed output stream
            PgpLiteralData.Binary,
            fileName,               // "filename" to store
            clearData.Length,       // length of clear data
            DateTime.UtcNow         // current time
            );

            pOut.Write(clearData, 0, clearData.Length);
            pOut.Close();

            comData.Close();

            return bOut.ToArray();
        }
    }