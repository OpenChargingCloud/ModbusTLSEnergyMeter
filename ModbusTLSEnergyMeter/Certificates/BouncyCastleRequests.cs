/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of the Modbus/TLS Energy Meter <https://github.com/OpenChargingCloud/ModbusTLSEnergyMeter>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities.IO.Pem;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// The certificate signing requests .NET will not build.
    /// </summary>
    /// <remarks>
    /// <see cref="System.Security.Cryptography.X509Certificates.CertificateRequest"/>
    /// takes an RSA or an ECDsa key, and in .NET 10 an ML-DSA or SLH-DSA one
    /// behind an API marked experimental - "may change or be removed in future
    /// updates". It takes no Edwards curve at all. BouncyCastle builds all of
    /// them with one stable interface, comes in with ChargyCore already, and is
    /// what the signing keys of this meter are made with, so this is one
    /// library rather than a second.
    ///
    /// A certificate over one of these keys cannot be shown by either of this
    /// meter's listeners: .NET's SslStream authenticates a server with RSA or
    /// ECDSA, and nothing here can change that. The store knows - such an entry
    /// never becomes the certificate a listener is handed, because its private
    /// key is never attached to it - and the page says so where somebody
    /// chooses. What these are for is a certificate used somewhere else, and
    /// for having something to point a piece of PKI software at.
    /// </remarks>
    public static class BouncyCastleRequests
    {

        #region Data

        /// <summary>
        /// What this builds, and what each one is called when it signs.
        /// </summary>
        /// <remarks>
        /// The signature algorithm name is not decoration: an ML-DSA key of one
        /// parameter set signed with the name of another is refused outright,
        /// which is the right answer and worth getting from a table rather than
        /// from a guess.
        /// </remarks>
        private static readonly Dictionary<String, String> algorithms = new () {
            { "ed25519",  "Ed25519"   },
            { "ed448",    "Ed448"     },
            { "mldsa44",  "ML-DSA-44" },
            { "mldsa65",  "ML-DSA-65" },
            { "mldsa87",  "ML-DSA-87" }
        };

        #endregion

        #region Properties

        /// <summary>
        /// The key types this builds requests for, weakest first.
        /// </summary>
        public static IEnumerable<String> KeyTypes

            => algorithms.Keys;

        #endregion


        #region Handles(KeyType)

        /// <summary>
        /// Whether this is one of the key types .NET cannot build a request for.
        /// </summary>
        public static Boolean Handles(String? KeyType)

            => KeyType is not null && algorithms.ContainsKey(KeyType);

        #endregion

        #region Create(Subject, DNSNames, IPAddresses, KeyType)

        /// <summary>
        /// Make a key and write a certificate signing request for it.
        /// </summary>
        /// <param name="Subject">The subject to ask for, e.g. "CN=meter7.lan, O=Acme".</param>
        /// <param name="DNSNames">The names a peer will dial.</param>
        /// <param name="IPAddresses">The addresses a peer will dial.</param>
        /// <param name="KeyType">One of <see cref="KeyTypes"/>.</param>
        /// <returns>The request and the private key, both PEM encoded.</returns>
        public static (String RequestPEM, String KeyPEM) Create(String               Subject,
                                                                IEnumerable<String>  DNSNames,
                                                                IEnumerable<String>  IPAddresses,
                                                                String               KeyType)
        {

            if (!algorithms.TryGetValue(KeyType, out var signatureAlgorithm))
                throw new ArgumentException($"'{KeyType}' is not one of: {String.Join(", ", KeyTypes)}.", nameof(KeyType));

            var pair       = GenerateKeyPair(KeyType);

            var request    = new Pkcs10CertificationRequest(
                                 new Asn1SignatureFactory(signatureAlgorithm, pair.Private, new SecureRandom()),
                                 new X509Name(Subject),
                                 pair.Public,
                                 new DerSet(
                                     new AttributePkcs(
                                         PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                                         new DerSet(Extensions(DNSNames, IPAddresses))
                                     )
                                 )
                             );

            // Checked here rather than left for the CA to discover. A request
            // that does not verify against its own key is a request nobody can
            // do anything with, and this is the one moment both halves are in
            // the same place.
            if (!request.Verify())
                throw new CryptographicException($"The {KeyType} signing request did not verify against its own key.");

            return (
                       PEM("CERTIFICATE REQUEST", request.GetEncoded()),
                       PEM("PRIVATE KEY",         PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded())
                   );

        }

        #endregion

        #region PublicKeyOf(KeyPEM)

        /// <summary>
        /// The SubjectPublicKeyInfo belonging to a private key of one of these
        /// algorithms.
        /// </summary>
        /// <remarks>
        /// How a certificate is matched to the key that asked for it. .NET
        /// matches by trying to attach the key to the certificate, which it
        /// cannot do for any of these - but the public key is in both, and two
        /// SubjectPublicKeyInfos being equal is the same proof by a shorter
        /// route.
        /// </remarks>
        public static Byte[] PublicKeyOf(String KeyPEM)
        {

            var reader     = new PemReader(new StringReader(KeyPEM));
            var pem        = reader.ReadPemObject()
                                 ?? throw new CryptographicException("That private key is not PEM encoded.");

            var privateKey = PrivateKeyFactory.CreateKey(pem.Content);

            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                       PublicKeyOf(privateKey)
                   ).GetDerEncoded();

        }

        #endregion


        #region (private static) GenerateKeyPair(KeyType) / PublicKeyOf(PrivateKey)

        private static AsymmetricCipherKeyPair GenerateKeyPair(String KeyType)
        {

            var random = new SecureRandom();

            switch (KeyType)
            {

                case "ed25519":
                {
                    var generator = new Ed25519KeyPairGenerator();
                    generator.Init(new Ed25519KeyGenerationParameters(random));
                    return generator.GenerateKeyPair();
                }

                case "ed448":
                {
                    var generator = new Ed448KeyPairGenerator();
                    generator.Init(new Ed448KeyGenerationParameters(random));
                    return generator.GenerateKeyPair();
                }

                default:
                {

                    var parameters = KeyType switch {
                                         "mldsa44"  => MLDsaParameters.ml_dsa_44,
                                         "mldsa65"  => MLDsaParameters.ml_dsa_65,
                                         "mldsa87"  => MLDsaParameters.ml_dsa_87,
                                         _          => throw new ArgumentException($"Unknown key type '{KeyType}'!", nameof(KeyType))
                                     };

                    var generator  = new MLDsaKeyPairGenerator();
                    generator.Init(new MLDsaKeyGenerationParameters(random, parameters));
                    return generator.GenerateKeyPair();

                }

            }

        }

        /// <summary>
        /// The public half of a private key, which none of these types hands
        /// out through a common interface.
        /// </summary>
        private static AsymmetricKeyParameter PublicKeyOf(AsymmetricKeyParameter PrivateKey)

            => PrivateKey switch {
                   Ed25519PrivateKeyParameters ed25519  => ed25519.GeneratePublicKey(),
                   Ed448PrivateKeyParameters   ed448    => ed448.  GeneratePublicKey(),
                   MLDsaPrivateKeyParameters   mldsa    => mldsa.  GetPublicKey(),
                   _                                    => throw new CryptographicException(
                                                               $"'{PrivateKey.GetType().Name}' is not a key this meter made.")
               };

        #endregion

        #region (private static) Extensions(DNSNames, IPAddresses) / PEM(Label, DER)

        /// <summary>
        /// The extensions every server certificate this meter asks for wants.
        /// </summary>
        /// <remarks>
        /// The same set the .NET path asks for, with one difference that is not
        /// an oversight: no keyEncipherment. Ed25519, Ed448 and ML-DSA sign and
        /// do not encrypt, so a key usage saying otherwise would be a claim
        /// about the key that is not true.
        /// </remarks>
        private static X509Extensions Extensions(IEnumerable<String>  DNSNames,
                                                 IEnumerable<String>  IPAddresses)
        {

            var extensions = new Dictionary<DerObjectIdentifier, X509Extension>();

            var names      = new List<GeneralName>();

            foreach (var name in DNSNames)
                names.Add(new GeneralName(GeneralName.DnsName, name));

            foreach (var address in IPAddresses)
                if (NetIPAddress.TryParse(address, out _))
                    names.Add(new GeneralName(GeneralName.IPAddress, address));

            if (names.Count > 0)
                extensions.Add(
                    X509Extensions.SubjectAlternativeName,
                    new X509Extension(false, new DerOctetString(new GeneralNames([.. names])))
                );

            extensions.Add(
                X509Extensions.BasicConstraints,
                new X509Extension(true, new DerOctetString(new BasicConstraints(false)))
            );

            extensions.Add(
                X509Extensions.KeyUsage,
                new X509Extension(true, new DerOctetString(new KeyUsage(KeyUsage.DigitalSignature)))
            );

            // serverAuth: this certificate is for a listener, and a CA that
            // reads the request is being told so rather than having to guess.
            extensions.Add(
                X509Extensions.ExtendedKeyUsage,
                new X509Extension(false, new DerOctetString(new ExtendedKeyUsage(KeyPurposeID.id_kp_serverAuth)))
            );

            return new X509Extensions(extensions);

        }

        private static String PEM(String  Label,
                                  Byte[]  DER)
        {

            var text   = new StringWriter();
            var writer = new PemWriter(text);

            writer.WriteObject(new PemObject(Label, DER));
            writer.Writer.Flush();

            return text.ToString();

        }

        #endregion

    }

}
