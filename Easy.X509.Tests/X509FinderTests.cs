using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace Easy.X509.Tests
{
    [TestFixture]
    class X509FinderTests
    {
        private static object[] UseCase =
        {
            new object[] {new X509Selector(X509Selector.ByThumbprint("62B860AD1F0DF8ABABB6991A27BBAAEC1E4E4DBD"))},
            new object[] {new X509Selector(X509Selector.BySerialNumber("516BEA27A5E4D68742B49EA5D5DA358D"))},
        };

        [Explicit]
        [TestCaseSource(nameof(UseCase))]
        public void Given_thumbprint_should_find_certificates_in_all_stores_and_locations(X509Selector selector)
        {
            X509Finder finder = new X509Finder();

            // This certificate is used for dev on IIS. You can change it to another one.
            IList<X509Certificate2> certs = finder.FindCertificates(selector);

            Assert.That(certs.Count > 0);

            X509Certificate2 cert = certs[0];
            Assert.That(cert.FriendlyName == "IIS Express Development Certificate");
            Assert.That(cert.HasPrivateKey);
            Assert.That(cert.IssuerName.Name == "CN=localhost");
            Assert.That(cert.SerialNumber == "516BEA27A5E4D68742B49EA5D5DA358D");
            Assert.That(cert.SignatureAlgorithm.FriendlyName == "sha256RSA");
        }
    }
}
