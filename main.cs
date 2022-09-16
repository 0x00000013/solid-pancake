using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Net;
using CommandLine;

class EventListner
{

    public class Options
    {
        [Option('d', "directory", Required = false, Default = "C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine",
                HelpText = "Directory to look for quarantine folders.")]
        public string? Directory { get; set; }

        [Option('u', "url", Required = false, Default = "http://username:password@localhost:80",
                HelpText = "webdav endpoint in full URI mode. put file:/// URI to store on local disk")]
        public string? Url { get; set; }

        [Option('p', "proxy", Required = false, Default = true,
                HelpText = "respect system proxy")]
        public bool? Proxy { get; set; }

    }



    public static Options? o;
    static void Main(string[] args)
    {

        o = Parser.Default.ParseArguments<Options>(args).Value;

        while (true)
        {
            try
            {
                string query = "*[System/EventID=1117]";
                var logQuery = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, query);
                EventLogWatcher watcher = new EventLogWatcher(logQuery);

                watcher.EventRecordWritten += NewEventEntryWritten;

                watcher.Enabled = true;
                //just to make the app wait to see the event hit
                Console.WriteLine("daemon started.. waiting for an event");
                //todo: this should wait forever and have error handling so it never crashes and dies
                System.Threading.Thread.Sleep(Timeout.Infinite);
            }
            catch (Exception ex)
            {
                Console.WriteLine("encountered an error: " + ex);
            }
        }
    }

    private static string ToRfc3339StringNow()
    {
        return DateTime.Now.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz");
    }

    private static byte[] mseKsa()
    {
        var staticKey = new byte[] {0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C,
                    0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83,
                    0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD,
                    0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96, 0x97, 0x90,
                    0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53, 0x71,
                    0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D,
                    0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB,
                    0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE,
                    0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0,
                    0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
                    0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2,
                    0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D,
                    0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9,
                    0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2,
                    0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC, 0x0E, 0xCB, 0x0A,
                    0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
                    0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26,
                    0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3,
                    0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36, 0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C,
                    0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53};
        var ret = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            ret[i] = (byte)(i);
        }
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + ret[i] + staticKey[i]) % 256;
            byte tmp = ret[i];
            ret[i] = ret[j];
            ret[j] = tmp;
        }
        return ret;
    }

    private static byte[] rc4Decrypt(byte[] data)
    {
        byte[] pKey = mseKsa();
        var ret = new byte[data.Length];
        int i = 0;
        int j = 0;
        for (int k = 0; k < data.Length; k++)
        {
            i = (i + 1) % 256;
            j = (j + pKey[i]) % 256;
            byte tmp = pKey[i];
            pKey[i] = pKey[j];
            pKey[j] = tmp;
            byte val = pKey[(pKey[i] + pKey[j]) % 256];
            ret[k] = (byte)(val ^ data[k]);
        }
        return ret;
    }

    // Search is a pattern matching for a bytestream
    private static int Search(byte[] src, byte[] pattern)
    {
        int maxFirstCharSlot = src.Length - pattern.Length + 1;
        for (int i = 0; i < maxFirstCharSlot; i++)
        {
            if (src[i] != pattern[0]) // compare only first byte
                continue;

            // found a match on first byte, now try to match rest of the pattern
            for (int j = pattern.Length - 1; j >= 1; j--)
            {
                if (src[i + j] != pattern[j]) break;
                if (j == 1) return i;
            }
        }
        return -1;
    }

    private static (string path, string type, string hash) getEntry(byte[] data)
    {
        (string path, string type, string hash) output = ("", "", "");
        try
        {


            // path ends with a UTF-16 null terminator
            int pathPosIdx = Search(data, new byte[] { 0x00, 0x00, 0x00 });

            output.path = System.Text.Encoding.Default.GetString(data.Take(pathPosIdx).ToArray());

            // normalises the path if it starts with \\?\ or something similar. 
            if (output.path.Substring(3).StartsWith("?\\"))
            {
                output.path = output.path.Substring(7);
            }

            // skip already computed bytes
            // the extra 4 is for the number of entries field 
            data = data.Skip(pathPosIdx + 5).ToArray();

            // type variable ends with a single null terminator
            int typePosIdx = Search(data, new byte[] { 0x00, 0x00 });
            output.type = System.Text.Encoding.Default.GetString(data.Take(typePosIdx).ToArray()).TrimStart('\0');

            // skip already computed bytes
            data = data.Skip(typePosIdx + output.type.Length + 1).ToArray();
            // skip metadata and padding bytes
            data = data.Skip(data.Length % 4).ToArray();

            output.hash = Convert.ToHexString(data.Take(20).ToArray());

        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
        return (output.path, output.type, output.hash);

    }

    private static (byte[] malFile, ulong malFileLength) unpackMalware(byte[] packed)
    {
        (byte[] malFile, ulong malFileLength) output = (new byte[] { }, 0);
        // todo: in here, decryptedPayload can be actively scanned by defender, and kill our agent through heuristics
        byte[] decryptedPayload = rc4Decrypt(packed);
        int sdLen = decryptedPayload.Skip(8).ToArray()[0];
        int headerLen = 0x28 + sdLen;
        output.malFileLength = BitConverter.ToUInt64(decryptedPayload.Skip(sdLen).Skip(0x1c).Take(8).ToArray());
        output.malFile = decryptedPayload.Skip(headerLen).Take((int)output.malFileLength).ToArray();
        return output;
    }


    private static string grabQuarantineFile((string path, string type, string hash) offense)
    {
        try
        {
            string hashPrefix = new string(offense.hash.Take(2).ToArray());
            string quarFile = Path.Combine(o.Directory, "ResourceData", hashPrefix, offense.hash);
            if (!File.Exists(quarFile))
            {
                Console.WriteLine("file not found");
                return "";
            }
            byte[] packedMalBytes = { };
            packedMalBytes = File.ReadAllBytes(quarFile);
            var unpacked = unpackMalware(packedMalBytes);

            var pubKey = PGP.ReadPublicKey(new MemoryStream(Encoding.UTF8.GetBytes(PGP.PublicKey)));
            return System.Text.Encoding.Default.GetString(PGP.Encrypt(unpacked.malFile, pubKey, true, true));
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            return "";
        }
    }

    private static void uploadFile(string content, string filename, string uri)
    {
        var url = new Uri(uri);
        if (url.Scheme == "file")
        {
            try
            {
                string outPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), filename);
                Console.WriteLine("Writing the sample to " + outPath);
                File.WriteAllText(outPath, content);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

        }
        else
        {
            using (var client = new System.Net.WebClient())
            {
                try
                {
                    var creds = url.UserInfo.Split(":");
                    client.Credentials = new NetworkCredential(creds[0], creds[1]);

                    client.UploadString(uri + "/" + filename, "PUT", content);
                    Console.WriteLine("Upload successful");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
            }
        }
    }

    private static void EventActionChain(string rawEvent)
    {
        try
        {
            // get the event details here, and find the path inside the event
            // https://reversingfun.com/posts/how-to-extract-quarantine-files-from-windows-defender/
            // get the latest file inside "Entries" folder and decrypt it, and match the path 
            var entriesDir = new DirectoryInfo(Path.Combine(o.Directory, "Entries"));
            var latestEntry = (from f in entriesDir.GetFiles()
                               orderby f.LastWriteTime descending
                               select f).First();
            byte[] latestEntryBytes = { };
            try
            {
                latestEntryBytes = File.ReadAllBytes(latestEntry.FullName);
                //todo: check to see if the entry matches the filename we find here somehow
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            // this gives out the header of the entry, which contains
            // two 8 byte integer numbers before and after 0x28 byte
            // which are the lengths of other sections
            byte[] decryptedLengths = rc4Decrypt(latestEntryBytes.Take(0x3c).ToArray());
            // Console.WriteLine(Convert.ToHexString(decryptedLengths));

            uint firstLength = BitConverter.ToUInt32(decryptedLengths.Take(0x28 + 4).TakeLast(4).ToArray());
            uint secondLength = BitConverter.ToUInt32(decryptedLengths.Take(0x28 + 8).TakeLast(4).ToArray());

            byte[] firstSectionBytes = rc4Decrypt(latestEntryBytes.Take(0x3c + (int)firstLength).TakeLast((int)firstLength).ToArray());
            // data1 is a struct 
            UInt64 fileTime = BitConverter.ToUInt64(firstSectionBytes.Take(0x28).TakeLast(8).ToArray());
            string detection = System.Text.Encoding.Default.GetString(firstSectionBytes.Skip(0x34).ToArray());
            // filetime: 8 bytes
            // detection: the rest

            // get the actual file from "ResourceData" and try to decrypt it in RAM and re-encrypt the file with a public key 
            byte[] secondSectionBytes = rc4Decrypt(latestEntryBytes.Take(0x3c + (int)firstLength + (int)secondLength).TakeLast((int)secondLength).ToArray());
            // filepath, count, and offenses are here. for each offense, there's a file path, hash and filetype recorded.
            uint count = BitConverter.ToUInt32(secondSectionBytes);
            var offsets = new int[count];
            for (int i = 0; i < count; i++)
            {
                offsets[i] = (int)BitConverter.ToUInt32(secondSectionBytes.Skip(4 + 4 * i).ToArray());
                var offense = getEntry(secondSectionBytes.Skip(offsets[i]).ToArray());
                if (offense.type == "file")
                {
                    Console.WriteLine(offense);
                    // todo: file is PGP encrypted. need a way to write it to a file or upload it to the cloud
                    // Console.WriteLine(grabQuarantineFile(offense));


                    // string outPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), offense.hash + ".mal.pgp");
                    // Console.WriteLine("Writing the sample to " + outPath);
                    // File.WriteAllText(outPath, grabQuarantineFile(offense));
                    Console.WriteLine(rawEvent);
                    string filename = System.Net.Dns.GetHostName() + "--" + ToRfc3339StringNow() + "--" + offense.hash + ".mal.pgp";
                    uploadFile(grabQuarantineFile(offense), filename, o.Url);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }

    private static void NewEventEntryWritten(object sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            String message = e.EventRecord.FormatDescription();
            // Console.WriteLine(message);
            Console.WriteLine("New Event recieved, processing...");
            //todo: this should pass in the message and some checks should be done between the event and the parsed output
            EventActionChain(message);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
        }
    }
}