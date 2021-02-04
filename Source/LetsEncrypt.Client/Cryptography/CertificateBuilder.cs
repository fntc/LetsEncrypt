using LetsEncrypt.Client.Entities;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
#if NETSTANDARD2_0
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Tls;
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
            Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory
                (PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id, keyPair.Private);

            var cGenerator = new X509V3CertificateGenerator();

            cGenerator.SetSubjectDN(new X509Name("CN=" + cn));

            cGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            cGenerator.SetPublicKey(keyPair.Public);

            
            //cGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, true, new SubjectKeyIdentifier(keyPair.Public));
            //req.CertificateExtensions.Add(
            //    new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

            var sanb = new List<GeneralName>();
            foreach (var subjectAlternativeName in subjectAlternativeNames)
            {
                sanb.Add(new GeneralName(GeneralName.DnsName, subjectAlternativeName));
            }
           
            cGenerator.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(sanb.ToArray()));
            var cert = cGenerator.Generate(signatureFactory);
            return cert.GetEncoded();

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