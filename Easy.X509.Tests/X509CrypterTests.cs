using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Easy.X509.Tests
{
    [TestFixture]
    internal class X509CrypterTests
    {
        [Test]
        public void Text_should_encrypt_and_decrypt_with_certificate()
        {
            string certificateFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "certificate.pfx");

            X509Certificate2 cert = new X509Certificate2(certificateFile, "1234", X509KeyStorageFlags.Exportable);

            string mySecret = "Something secret";

            X509Crypter crypt = new X509Crypter(cert);
            string encryptedText = crypt.Encrypt(mySecret);
            string decryptedText = crypt.Decrypt(encryptedText);

            Assert.That(decryptedText == mySecret);
        }

        [Test]
        public void Text_should_be_signed_then_verified_as_signed()
        {
            string certificateFile = Path.Combine(TestContext.CurrentContext.TestDirectory, "certificate.pfx");

            X509Certificate2 cert = new X509Certificate2(certificateFile, "1234", X509KeyStorageFlags.Exportable);

            string plainText = "Something to sign";

            X509Crypter crypt = new X509Crypter(cert);
            string signedText = crypt.Sign(plainText);
            bool isSigned = crypt.VerifySignature(plainText, signedText);

            Assert.IsTrue(isSigned);
        }
    }
}
