using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Easy.X509
{
    public class X509Selector
    {
        private readonly Func<X509Certificate2, bool> _selector;

        public static Func<string, Func<X509Certificate2, bool>> ByThumbprint = thumbprint => cert => string.Compare(cert.Thumbprint,
                                                                                                                     thumbprint,
                                                                                                                     StringComparison.InvariantCultureIgnoreCase) == 0;

        public static Func<string, Func<X509Certificate2, bool>> BySerialNumber = serialNumber => cert => string.Compare(cert.SerialNumber,
                                                                                                                         serialNumber,
                                                                                                                         StringComparison.InvariantCultureIgnoreCase) == 0;

        public X509Selector(Func<X509Certificate2, bool> selector)
        {
            _selector = selector;
        }

        public bool Match(X509Certificate2 certificate)
        {
            return _selector(certificate);
        }
    }
}
