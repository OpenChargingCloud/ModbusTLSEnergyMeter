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
using System.Text;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Logging
{

    /// <summary>
    /// The key this meter signs its log with.
    /// </summary>
    /// <remarks>
    /// A key of its own rather than the one the Modbus/TLS listener uses. They
    /// answer different questions - "is this the meter I am talking to" and
    /// "did this meter write this line" - and a key that does both has to be
    /// replaced whenever either answer changes. The meter certificate also
    /// expires and is reissued, and a log signed with it would then need the
    /// old certificate kept for ever to stay checkable.
    ///
    /// ECDSA over P-256: small signatures, of which there is one per line.
    ///
    /// What this is worth is bounded, and the bound is worth saying plainly.
    /// The key sits next to the log it signs, so somebody who can write that
    /// directory can also read the key and sign a log of their own invention.
    /// Signing catches a file that was edited, truncated, reordered or copied
    /// from another meter; it does not catch an attacker who took the key. To
    /// be worth more, the head of the chain has to be written down somewhere
    /// this meter cannot reach - see <see cref="LogStore.Head"/>, which exists
    /// to be exported.
    /// </remarks>
    public sealed class LogSigner : IDisposable
    {

        #region Data

        /// <summary>
        /// The file the private key lives in, below the log directory.
        /// </summary>
        public const String  KeyFileName        = "signing-key.pem";

        /// <summary>
        /// The file the public key is written to, so that whoever checks the
        /// log does not have to be handed it separately.
        /// </summary>
        public const String  PublicKeyFileName  = "signing-key.pub.pem";

        private readonly ECDsa  key;
        private          Boolean disposed;

        #endregion

        #region Properties

        /// <summary>
        /// The public key, as PEM, for whoever checks the log.
        /// </summary>
        public String  PublicKeyPem  { get; }

        /// <summary>
        /// A short name for that key: the first 16 hex digits of the SHA-256 of
        /// its SubjectPublicKeyInfo.
        /// </summary>
        /// <remarks>
        /// Written into every entry, so that a file signed by one key and a
        /// file signed by another can be told apart without trying both - and
        /// so that a log continued after the key was replaced says where that
        /// happened.
        /// </remarks>
        public String  KeyId         { get; }

        /// <summary>
        /// Whether the key was made now rather than read from disk.
        /// </summary>
        public Boolean IsNew         { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Open the signing key in the given directory, making one if there is
        /// none yet.
        /// </summary>
        /// <param name="Directory">Where the key lives.</param>
        public LogSigner(String Directory)
        {

            var keyPath = Path.Combine(Directory, KeyFileName);

            key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            if (File.Exists(keyPath))
            {
                key.ImportFromPem(File.ReadAllText(keyPath));
                IsNew = false;
            }

            else
            {

                File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem() + "\n");
                Protect(keyPath);

                IsNew = true;

            }

            PublicKeyPem = key.ExportSubjectPublicKeyInfoPem() + "\n";
            KeyId        = Convert.ToHexString(
                               SHA256.HashData(key.ExportSubjectPublicKeyInfo())
                           )[..16].ToLowerInvariant();

            // Beside the private key, because the first question anybody
            // checking a log asks is "which key, and where do I get it".
            var publicPath = Path.Combine(Directory, PublicKeyFileName);

            if (!File.Exists(publicPath))
                File.WriteAllText(publicPath, PublicKeyPem);

        }

        #endregion


        #region Sign(Payload)

        /// <summary>
        /// The signature over one line, base64.
        /// </summary>
        public String Sign(ReadOnlySpan<Byte> Payload)

            => Convert.ToBase64String(
                   key.SignData(Payload, HashAlgorithmName.SHA256)
               );

        #endregion

        #region Verify(Payload, Signature)

        /// <summary>
        /// Whether that signature belongs to that line and this key.
        /// </summary>
        public Boolean Verify(ReadOnlySpan<Byte>  Payload,
                              String              Signature)
        {

            try
            {
                return key.VerifyData(Payload, Convert.FromBase64String(Signature), HashAlgorithmName.SHA256);
            }
            catch
            {
                // A signature that is not even base64 is a signature that does
                // not check out, which is the answer either way.
                return false;
            }

        }

        #endregion

        #region (static) Verify(Payload, Signature, PublicKeyPem)

        /// <summary>
        /// The same, with a public key from somewhere else - for whoever checks
        /// a log away from the meter that wrote it.
        /// </summary>
        public static Boolean Verify(ReadOnlySpan<Byte>  Payload,
                                     String              Signature,
                                     String              PublicKeyPem)
        {

            try
            {

                using var key = ECDsa.Create();
                key.ImportFromPem(PublicKeyPem);

                return key.VerifyData(Payload, Convert.FromBase64String(Signature), HashAlgorithmName.SHA256);

            }
            catch
            {
                return false;
            }

        }

        #endregion

        #region (static) HashOf(Payload)

        /// <summary>
        /// The SHA-256 of one line, base64 - which is what the next line points
        /// back at.
        /// </summary>
        public static String HashOf(ReadOnlySpan<Byte> Payload)

            => Convert.ToBase64String(SHA256.HashData(Payload));


        /// <summary>
        /// The same, for a line given as text.
        /// </summary>
        public static String HashOf(String Payload)

            => HashOf(Encoding.UTF8.GetBytes(Payload));

        #endregion

        #region (private static) Protect(Path)

        /// <summary>
        /// Take the key away from everybody but its owner.
        /// </summary>
        /// <remarks>
        /// A private key that the whole machine may read is one that the whole
        /// machine may sign with. Unix only: Windows inherits the directory's
        /// ACL, and setting one properly is more than this needs.
        /// </remarks>
        private static void Protect(String Path)
        {

            if (OperatingSystem.IsWindows())
                return;

            try
            {
                File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            catch
            {
                // A file system with no notion of modes - a mounted share, say.
                // Worth trying, not worth failing a start over.
            }

        }

        #endregion

        #region Dispose()

        public void Dispose()
        {

            if (disposed)
                return;

            disposed = true;
            key.Dispose();

        }

        #endregion

    }

}
