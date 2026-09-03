using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HookBypass
{
    public static class Encryptor
    {
        public static void Main(string[] args)
        {
            try
            {
                if (args.Length < 2)
                {
                    Console.Error.WriteLine("Usage: Encryptor.exe <input.bin> <output.enc> [--key-hex <64hex>] [--iv-hex <32hex>] [--cs-out <file.cs>] [--verify]");
                    Environment.Exit(2);
                }

                string inputPath = args[0];
                string outputPath = args[1];
                string keyHex = null, ivHex = null, csOut = null;
                bool verify = false;

                for (int i = 2; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "--key-hex": keyHex = args[++i]; break;
                        case "--iv-hex": ivHex = args[++i]; break;
                        case "--cs-out": csOut = args[++i]; break;
                        case "--verify": verify = true; break;
                        default:
                            Console.Error.WriteLine("Unknown option: " + args[i]);
                            Environment.Exit(2);
                            break;
                    }
                }

                byte[] plain = File.ReadAllBytes(inputPath);
                if (plain.Length == 0) throw new InvalidOperationException("Input file is empty.");

                byte[] key, iv;
                if (keyHex != null)
                {
                    key = HexToBytes(keyHex);
                    if (key.Length != 32) throw new InvalidOperationException("--key-hex must be 64 hex chars (32 bytes).");
                }
                else key = RandomBytes(32);

                if (ivHex != null)
                {
                    iv = HexToBytes(ivHex);
                    if (iv.Length != 16) throw new InvalidOperationException("--iv-hex must be 32 hex chars (16 bytes).");
                }
                else iv = RandomBytes(16);

                byte[] encrypted = AesEncrypt(plain, key, iv);
                File.WriteAllBytes(outputPath, encrypted);
                File.WriteAllText(outputPath + ".key", BytesToHex(key) + Environment.NewLine + BytesToHex(iv) + Environment.NewLine);

                if (csOut != null)
                {
                    File.WriteAllText(csOut, BuildPayloadData(key, iv, encrypted));
                }

                Console.WriteLine("input     : " + inputPath);
                Console.WriteLine("input_len : " + plain.Length);
                Console.WriteLine("output    : " + outputPath);
                Console.WriteLine("output_len: " + encrypted.Length);
                Console.WriteLine("key_hex   : " + BytesToHex(key));
                Console.WriteLine("iv_hex    : " + BytesToHex(iv));

                if (verify)
                {
                    byte[] roundtrip = AesDecrypt(encrypted, key, iv);
                    bool ok = BytesEqual(plain, roundtrip);
                    Console.WriteLine("verify    : " + (ok ? "PASS" : "FAIL"));
                    Environment.Exit(ok ? 0 : 1);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: " + ex.Message);
                Environment.Exit(1);
            }
        }

        public static byte[] RandomBytes(int count)
        {
            byte[] buf = new byte[count];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(buf);
            return buf;
        }

        public static byte[] AesEncrypt(byte[] plain, byte[] key, byte[] iv)
        {
            using (var aes = new RijndaelManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (var enc = aes.CreateEncryptor())
                    return enc.TransformFinalBlock(plain, 0, plain.Length);
            }
        }

        public static byte[] AesDecrypt(byte[] cipher, byte[] key, byte[] iv)
        {
            using (var aes = new RijndaelManaged())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                aes.IV = iv;
                using (var dec = aes.CreateDecryptor())
                    return dec.TransformFinalBlock(cipher, 0, cipher.Length);
            }
        }

        public static byte[] HexToBytes(string hex)
        {
            if (hex == null || (hex.Length % 2) != 0)
                throw new ArgumentException("Invalid hex string.");
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        public static string BytesToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static string BytesToCsArray(byte[] data, string indent)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                if (i % 12 == 0) sb.Append(Environment.NewLine).Append(indent);
                sb.Append("0x").Append(data[i].ToString("x2"));
                if (i + 1 < data.Length) sb.Append(", ");
            }
            sb.Append(Environment.NewLine);
            return sb.ToString();
        }

        public static string BuildPayloadData(byte[] key, byte[] iv, byte[] encrypted)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// Auto-generated by HookBypass.Encryptor — AES-256-CBC payload data.");
            sb.AppendLine("// Key/IV are random per-run unless --key-hex/--iv-hex are supplied.");
            sb.AppendLine("namespace HookBypass");
            sb.AppendLine("{");
            sb.AppendLine("    public static class PayloadData");
            sb.AppendLine("    {");
            sb.AppendLine("        public static readonly byte[] Key = {").Append(BytesToCsArray(key, "            ")).AppendLine("        };");
            sb.AppendLine("        public static readonly byte[] IV = {").Append(BytesToCsArray(iv, "            ")).AppendLine("        };");
            sb.AppendLine("        public static readonly byte[] Encrypted = {").Append(BytesToCsArray(encrypted, "            ")).AppendLine("        };");
            sb.AppendLine("    }");
            sb.AppendLine("}");
            return sb.ToString();
        }

        public static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
