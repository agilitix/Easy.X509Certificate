using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Easy.X509
{
    public class X509Crypter
    {
        public X509Certificate2 Certificate { get; }

        public X509Crypter(X509Certificate2 certificate)
        {
            Certificate = certificate;
        }

        public string Sign(string textToSign)
        {
            using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider())
            {
                string xmlKey = PrivateKeyToXml();
                provider.FromXmlString(xmlKey);
                byte[] plainBytes = Encoding.UTF8.GetBytes(textToSign);
                byte[] cipherBytes = provider.SignData(plainBytes, new SHA1CryptoServiceProvider());
                string base64 = Convert.ToBase64String(cipherBytes);
                return base64;
            }
        }

        public bool VerifySignature(string plainText, string base64Signature)
        {
            using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider())
            {
                string xmlKey = PrivateKeyToXml();
                provider.FromXmlString(xmlKey);
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] signedBytes = Convert.FromBase64String(base64Signature);
                return provider.VerifyData(plainBytes, new SHA1CryptoServiceProvider(), signedBytes);
            }
        }

        public string Encrypt(string plainText)
        {
            using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider())
            {
                string xmlKey = PublicKeyToXml();
                provider.FromXmlString(xmlKey);
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherBytes = provider.Encrypt(plainBytes, false);
                string base64 = Convert.ToBase64String(cipherBytes);
                return base64;
            }
        }

        public string Decrypt(string base64Text)
        {
            using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider())
            {
                string xmlKey = PrivateKeyToXml();
                provider.FromXmlString(xmlKey);
                byte[] cipherBytes = Convert.FromBase64String(base64Text);
                byte[] plainBytes = provider.Decrypt(cipherBytes, false);
                string plainText = Encoding.UTF8.GetString(plainBytes);
                return plainText;
            }
        }

        private string PublicKeyToXml()
        {
            return Certificate.PublicKey.Key.ToXmlString(false);
        }

        private string PrivateKeyToXml()
        {
            return Certificate.PrivateKey.ToXmlString(true);
        }
    }
}
