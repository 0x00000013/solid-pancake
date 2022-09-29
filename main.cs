using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Net;
using CommandLine;
using Serilog;

using Azure.Storage.Blobs;
using System.Threading;

class EventListner
{
    public static Options o = new Options();
    // uploadedHashes is used to deduplicate files before uploading multiple instance of the same file
    public static List<string> uploadedHashes = new List<string>();
    public class Options
    {
        [Option('d', "directory", Required = false, Default = "C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine",
                HelpText = "Directory to look for quarantine folders.")]
        public string Directory { get; set; }

        [Option('a', "archive", Required = false, Default = "system::file:///C:/outputDir",
                HelpText = @"storage endpoint to store artifacts. Examples:
system::file:///C:/outputDir
webdav::https://username:password@localhost:80
blob::https://MYACCOUNT.blob.core.windows.net/MYCONTAINER/MYBLOB?MYSASTOKEN. SASTOKEN looks like this: sp=racwdlmeop&st=2022-09-29T00:55:42Z&se=2024-09-29T08:55:42Z&spr=https&sv=2021-06-08&sr=c&sig=SASSIGNATURE")]
        public string Archive { get; set; }

        [Option('l', "logtype", Required = false, Default = "system::console",
                HelpText = @"log endpoint. examples:
hec::https://hecreceiver.splunk.com:8443/service/collector?source=temp&sourcetype=temp&index=temp&token=MYTOKEN&channel=MY_CHANNEL_UUID
azure-analytics::https://ods.opinsights.azure.com?workspaceId=MY_CUSTOMER_ID&authenticationId=MY_SHARED_KEY&logName=MY_LOG_NAME
system::file:///C:/eventlistner.log
system::console")]
        public string Logtype { get; set; }

        [Option('e', "encryptionkey", Required = false, Default = "system::file:///pubkey.asc",
                HelpText = @"GPG public key to encrypt artifacts. Examples:
system::file:///pubkey.asc
url::https://github.com/mosajjal.gpg
base64::LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tCgo....gUFVCTElDIEtFWSBCTE9DSy0tLS0tCg==")]
        public string EncryptionKey { get; set; }
        public Org.BouncyCastle.Bcpg.OpenPgp.PgpPublicKey? GpgKey;
    }


    static void ValidateArgs(){
        try{
        //setting up logging
        var tmp = o.Logtype.Split("::", 2);
        var logType = tmp[0];
        var logUri = tmp[1];
        switch (logType)
        {
            case "hec":
                try
                {
                    var hecUrl = new Uri(logUri);
                    // hec::https://hecreceiver.splunk.com:8443/service/collector?source=temp&sourcetype=temp&index=temp&token=MYTOKEN&channel=MY_CHANNEL_UUID
                    var hecParams = System.Web.HttpUtility.ParseQueryString(hecUrl.Query);
                    var path = String.Format("{0}{1}{2}", hecUrl.Scheme, Uri.SchemeDelimiter, hecUrl.Authority, hecUrl.AbsolutePath);
                    Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .WriteTo.EventCollector(path + ":443", hecParams["token"], source: hecParams["source"],
                    sourceType: hecParams["sourcetype"], index: hecParams["index"],
                    host: System.Net.Dns.GetHostName(), renderTemplate: false)
                    .CreateLogger();
                    Console.WriteLine("writing logs to " + path + ":443");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("error", ex);
                }
                break;
            case "system":
                if (logUri.StartsWith("console"))
                {
                    Log.Logger = new LoggerConfiguration()
                    .MinimumLevel.Debug()
                    .WriteTo.Console()
                    .CreateLogger();
                }
                if (logUri.StartsWith("file"))
                {
                    try
                    {
                        var fileUrl = new Uri(logUri);
                        Log.Logger = new LoggerConfiguration()
                        .MinimumLevel.Debug()
                        .WriteTo.File(fileUrl.LocalPath)
                        .CreateLogger();
                        Console.WriteLine("writing logs to " + fileUrl.LocalPath);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("error", ex);
                    }
                }
                break;
            case "azure-analytics":
                var azureUrl = new Uri(logUri);
                // azure-analytics::https://ods.opinsights.azure.com?workspaceId=MY_CUSTOMER_ID&authenticationId=MY_SHARED_KEY&logName=MY_LOG_NAME
                var azureParams = System.Web.HttpUtility.ParseQueryString(azureUrl.Query);
                Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.AzureAnalytics(azureParams["workspaceId"], azureParams["authenticationId"])
                .CreateLogger();
                break;
            default:
                //todo: throw an error
                Log.Fatal("Logging could not be setup.. exiting");
                Environment.Exit(1);
                break;
        }

        // set up the PGP key
        tmp = o.EncryptionKey.Split("::", 2);
        var gpgType = tmp[0];
        var gpgUri = tmp[1];

        switch (gpgType)
        {
            case "system":
                o.GpgKey = PGP.ReadPublicKey(new MemoryStream(Encoding.UTF8.GetBytes(File.ReadAllText(new Uri(gpgUri).PathAndQuery))));
                Log.Information("Loaded GPG key from path");
            break;
            case "url":
                using (var wc = new System.Net.WebClient())
                o.GpgKey = PGP.ReadPublicKey(new MemoryStream(Encoding.UTF8.GetBytes(wc.DownloadString(gpgUri))));
                Log.Information("Loaded GPG key from the URL");
            break;
            case "base64":
                o.GpgKey = PGP.ReadPublicKey(new MemoryStream(Convert.FromBase64String(gpgUri)));
                Log.Information("Loaded GPG key from base64");
            break;
            default:
            Log.Fatal("GPG could not be setup.. exiting");
            Environment.Exit(1);
            break;
        }
        }
        catch (Exception e){
            Log.Fatal("Failed to validate Arguments.. exiting");
            Log.Fatal(e.ToString());
            Environment.Exit(1);
        }
    }

    static void QuarantineEventListener(){

        while (true)
        {
            try
            {
                string query = "*[System/EventID=1117]";
                var logQuery = new EventLogQuery("Microsoft-Windows-Windows Defender/Operational", PathType.LogName, query);
                EventLogWatcher watcher = new EventLogWatcher(logQuery);

                watcher.EventRecordWritten += QuarantineEventReceiver;

                watcher.Enabled = true;
                //just to make the app wait to see the event hit
                Log.Information("daemon started.. waiting for an event");
                //todo: this should wait forever and have error handling so it never crashes and dies
                System.Threading.Thread.Sleep(Timeout.Infinite);
            }
            catch (Exception ex)
            {
                Log.Information("encountered an error: " + ex);
            }
        }
    }

    static void Main(string[] args)
    {

        o = Parser.Default.ParseArguments<Options>(args).Value;
        //todo: exit on --help
        ValidateArgs();

        // start quarantine event listener
        Thread quarantineThread = new Thread(QuarantineEventListener);
        quarantineThread.Start();

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
            Log.Warning(ex.ToString());
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
                Log.Information("file not found");
                return "";
            }
            byte[] packedMalBytes = { };
            packedMalBytes = File.ReadAllBytes(quarFile);
            var unpacked = unpackMalware(packedMalBytes);

            return System.Text.Encoding.Default.GetString(PGP.Encrypt(unpacked.malFile, o.GpgKey, true, true));
        }
        catch (Exception ex)
        {
            Log.Warning(ex.ToString());
            return "";
        }
    }

    private static void uploadFile(string content, string filename, string hash, string archive)
    {
        var tmp = archive.Split("::", 2);
        var archType = tmp[0];
        var archUri = new Uri(tmp[1]);
        // get a temp file name and write the GPG content to it 
        var tmpFile = System.IO.Path.GetTempFileName();
        File.WriteAllText(tmpFile, content);

        switch (archType)
        {
            case "system":
                try
                {
                    // var url = new Uri(archUri);
                    if (archUri.Scheme == "file")
                    {

                        string outPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), filename);
                        Log.Information("Writing the sample to " + outPath);
                        File.WriteAllText(outPath, content);
                    }
                }
                catch (Exception ex)
                {
                    Log.Warning(ex.ToString());
                }
                break;

            case "webdav":
                using (var client = new System.Net.WebClient())
                {
                    try
                    {
                        // var url = new Uri(archUri);
                        var creds = archUri.UserInfo.Split(":");
                        client.Credentials = new NetworkCredential(creds[0], creds[1]);

                        client.UploadFile(archUri + "/" + filename, "PUT", tmpFile);
                        // client.UploadString(uri + "/" + filename, "PUT", content);
                        Log.Information("Upload successful");

                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex.ToString());
                    }
                }
                break;

            case "blob":

                try
                {
                    var newUri = new Uri(archUri.GetLeftPart(UriPartial.Authority) + archUri.LocalPath + "/" + filename + archUri.Query);
                    var blob = new BlobClient(newUri);
                    blob.Upload(tmpFile);
                    Log.Information("Upload successful");
                    uploadedHashes.Add(hash);

                }
                catch (Exception ex)
                {
                    Log.Warning(ex.ToString());
                }

                break;

            default:
                break;
        }


        //remove the temp file
        File.Delete(tmpFile);


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
                Log.Warning(ex.ToString());
            }
            // this gives out the header of the entry, which contains
            // two 8 byte integer numbers before and after 0x28 byte
            // which are the lengths of other sections
            byte[] decryptedLengths = rc4Decrypt(latestEntryBytes.Take(0x3c).ToArray());
            // Log.Information(Convert.ToHexString(decryptedLengths));

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
                    Log.Information(offense.ToString());
                    // todo: file is PGP encrypted. need a way to write it to a file or upload it to the cloud
                    // Log.Information(grabQuarantineFile(offense));


                    // string outPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), offense.hash + ".mal.pgp");
                    // Log.Information("Writing the sample to " + outPath);
                    // File.WriteAllText(outPath, grabQuarantineFile(offense));
                    Log.Information(rawEvent);
                    string filename = System.Net.Dns.GetHostName() + "--" + ToRfc3339StringNow() + "--" + offense.hash + ".mal.pgp";
                    if (uploadedHashes.Contains(offense.hash))
                    {
                        Log.Information("skipping duplicate upload");
                    }
                    else
                    {
                        uploadFile(grabQuarantineFile(offense), filename, offense.hash, o.Archive);
                    }
                }
                else
                {
                    Log.Information("non-file offense cought");
                    Log.Information(offense.ToString());
                }
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex.ToString());
        }
    }

    private static void QuarantineEventReceiver(object sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            String message = e.EventRecord.FormatDescription();
            // Log.Information(message);
            Log.Information("New Event recieved, processing...");
            //todo: this should pass in the message and some checks should be done between the event and the parsed output
            EventActionChain(message);
        }
        catch (Exception ex)
        {
            Log.Warning(ex.ToString());
        }
    }
}