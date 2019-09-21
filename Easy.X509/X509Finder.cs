using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Easy.X509
{
    public class X509Finder
    {
        public IList<X509Certificate2> FindCertificates(X509Selector selector)
        {
            StoreLocation[] locations = Enum.GetValues(typeof(StoreLocation))
                                            .Cast<StoreLocation>()
                                            .ToArray();
            StoreName[] stores = Enum.GetValues(typeof(StoreName))
                                     .Cast<StoreName>()
                                     .ToArray();

            IList<X509Certificate2> foundCertificates = new List<X509Certificate2>();

            foreach (StoreLocation storeLocation in locations)
            {
                foreach (StoreName storeName in stores)
                {
                    X509Store store = new X509Store(storeName, storeLocation);
                    try
                    {
                        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                        foreach (X509Certificate2 cert in store.Certificates)
                        {
                            if (selector.Match(cert))
                            {
                                foundCertificates.Add(cert);
                            }
                        }
                    }
                    catch
                    {
                        // ignored
                    }

                    store.Close();
                }
            }

            return foundCertificates;
        }
    }
}
