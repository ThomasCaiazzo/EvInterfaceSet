using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EvInterfaceSet
{
    public interface ITCPCom
    {
        void Initialize(string key, string iv);
        string SendTCPMessage(string location, int port, string data);
        string EncryptStringToBase64(string plaintext);
        string DecryptStringFromBase64(string base64text);
    };
    // Interface implementation.
    public class ManagedTCPComClass : ITCPCom
    { 
        public byte[] Key;
        public byte[] IV;
        public string EncryptStringToBase64(string plainText)
        {
            if (plainText == null || plainText.Length <= 0)
                return "Failed no text!";
            if (this.Key == null || this.Key.Length <= 0)
                return "No key!";
            if (this.IV == null || this.IV.Length <= 0)
                return "No IV";
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.ISO10126;
                rijAlg.KeySize = 256;
                rijAlg.BlockSize = 256;
                rijAlg.Key = this.Key;
                rijAlg.IV = this.IV;

                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted);
        }
        public string DecryptStringFromBase64(string base64text)
        {
            if (base64text == null || base64text.Length <= 0)
                return "Input not found!";
            if (this.Key == null || this.Key.Length <= 0)
                return "No Key!";
            if (this.IV == null || this.IV.Length <= 0)
                return "No IV";
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.ISO10126;
                rijAlg.KeySize = 256;
                rijAlg.BlockSize = 256;
                rijAlg.Key = this.Key;
                rijAlg.IV = this.IV;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(base64text)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
        public void Initialize(string key, string iv)
        {
           this.Key = Convert.FromBase64String(key);
           this.IV = Convert.FromBase64String(iv);
        }
        public string SendTCPMessage(string location, int port, string data)
        {
            try
            {
                TcpClient client = new TcpClient(location.ToString(), port);
                Stream s = client.GetStream();
                StreamWriter sw = new StreamWriter(s);
                sw.AutoFlush = true;
                sw.Write(EncryptStringToBase64(data));
                byte[] tmpbytes = new byte[s.Length];
                s.Read(tmpbytes, 1, (int)s.Length);
                s.Close();
                client.Close();
                return DecryptStringFromBase64(Encoding.ASCII.GetString(tmpbytes));
            }
            catch (Exception ex)
            {
                return ("Error:" + " " + ex.Message);
            }
        }
    }
}
