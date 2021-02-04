using LetsEncrypt.Client.Entities;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#if NETSTANDARD2_0
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
#endif
namespace LetsEncrypt.Client.Cryptography
{
    public static class CertificateBuilder
    {
        // Public Methods

        public static byte[] CreateSigningRequest(RSA rsa, string cn, List<string> subjectAlternativeNames)
        {
#if NETSTANDARD2_0
            var keyPair = DotNetUtilities.GetKeyPair(rsa);
            var csrAttrs = new List<Asn1Encodable>();

           
            var gnames = new List<GeneralName>();
            
            foreach (var n in subjectAlternativeNames)
                gnames.Add(new GeneralName(GeneralName.DnsName, n));

            var altNames = new GeneralNames(gnames.ToArray());

            var x509Ext = new X509Extensions(new Dictionary<DerObjectIdentifier, object>()
            {
                { X509Extensions.SubjectAlternativeName, new Org.BouncyCastle.Asn1.X509.X509Extension(false, new DerOctetString(altNames))}
            });

            csrAttrs.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                new DerSet(x509Ext)));
            
            var csr = new Pkcs10CertificationRequest(PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id,
                new X509Name($"CN={cn}"), keyPair.Public, new DerSet(csrAttrs.ToArray()), keyPair.Private);

            return csr.GetEncoded();
#endif
#if NETSTANDARD2_1

            CertificateRequest req = new CertificateRequest($"CN={cn}",
                   rsa,
                   HashAlgorithmName.SHA256,
                   RSASignaturePadding.Pkcs1);

            req.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

            var sanb = new SubjectAlternativeNameBuilder();
            foreach (var subjectAlternativeName in subjectAlternativeNames)
            {
                sanb.AddDnsName(subjectAlternativeName);
            }
            req.CertificateExtensions.Add(sanb.Build());

            return req.CreateSigningRequest();
#endif
        }

        public static byte[] Generate(RSA rsa, CertificateChain certificateChain, string password, X509ContentType certificateType)
        {
            var certificate = new X509Certificate2(certificateChain.CertificateBytes);
            var issuer = new X509Certificate2(certificateChain.IssuerBytes);

#if NETSTANDARD2_0
            certificate.PrivateKey = rsa;
#endif
#if NETSTANDARD2_1
            certificate = certificate.CopyWithPrivateKey(rsa);
#endif
            var collection = new X509Certificate2Collection();
            collection.Add(issuer);
            collection.Add(certificate);

            return collection.Export(certificateType, password);
        }
    }
}