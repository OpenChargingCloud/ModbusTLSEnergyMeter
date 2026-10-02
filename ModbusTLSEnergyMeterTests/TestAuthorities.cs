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
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// Takes the certificate authorities of a test PKI out of the
    /// intermediate CA stores again.
    /// </summary>
    /// <remarks>
    /// On Windows, SslStreamCertificateContext puts the intermediates of a
    /// chain the operating system cannot build into the CA store - the
    /// machine's when the process may write to it, else the user's - so that
    /// SChannel can send them - and nothing ever takes them out again. The
    /// meter's Modbus/TLS frontend builds such a context for its server
    /// certificate, and every new ModbusPKI() names its CAs after a fresh id,
    /// so every fixture run left one more CA behind. On 2026-10-02 the store
    /// held 1,347 "OCC SunSpec Modbus Issuing Device CA"s. Every load of the
    /// store costs about 0.14 ms of CPU per certificate in it, and it is
    /// loaded for every context built and every chain built with custom
    /// trust: TLS handshakes took seconds.
    /// </remarks>
    internal static class TestAuthorities
    {

        /// <summary>
        /// The CAs ModbusPKI.BuildPKI writes into its directory.
        /// </summary>
        private static readonly String[] PKIAuthorities = [
            "ca.crt",
            "issuing-device-ca.crt",
            "issuing-clients-ca.crt"
        ];


        #region RemoveInstalled(PKIDirectory)

        /// <summary>
        /// Remove the CAs of the PKI in the given directory from the
        /// intermediate CA stores, wherever they were put there.
        /// Call it after the meters that used the PKI are disposed, and before
        /// the directory is deleted. A removal that is refused is said in the
        /// test's output, and does not fail the test.
        /// </summary>
        /// <param name="PKIDirectory">The directory ModbusPKI.BuildPKI wrote.</param>
        public static void RemoveInstalled(String? PKIDirectory)
        {

            if (!OperatingSystem.IsWindows() || PKIDirectory is null || !Directory.Exists(PKIDirectory))
                return;

            var authorities = PKIAuthorities.
                                  Select (fileName => Path.Combine(PKIDirectory, fileName)).
                                  Where  (File.Exists).
                                  Select (X509CertificateLoader.LoadCertificateFromFile).
                                  ToArray();

            try
            {

                // The machine's store first: a process that may write to it,
                // as the elevated one on a CI runner does, is where .NET puts
                // them. And the user's store lists the machine's certificates
                // as well, but cannot take them out - "Access is denied" - so
                // they have to be gone from there before the user's store is
                // looked at.
                RemoveFrom(StoreLocation.LocalMachine, authorities);
                RemoveFrom(StoreLocation.CurrentUser,  authorities);

            }
            finally
            {
                foreach (var authority in authorities)
                    authority.Dispose();
            }

        }

        #endregion

        #region (private) RemoveFrom(Location, Authorities)

        /// <summary>
        /// Take these certificates out of the intermediate CA store of this
        /// location, where it can be written to.
        /// </summary>
        private static void RemoveFrom(StoreLocation                  Location,
                                       IEnumerable<X509Certificate2>  Authorities)
        {

            using var store = new X509Store(StoreName.CertificateAuthority, Location);

            try
            {
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            }
            catch (CryptographicException)
            {
                // Not this process's to write to - the machine's store, unelevated.
                return;
            }

            foreach (var authority in Authorities)
                foreach (var installed in store.Certificates.Find(X509FindType.FindByThumbprint, authority.Thumbprint, validOnly: false))
                {
                    try
                    {
                        store.Remove(installed);
                    }
                    catch (CryptographicException e)
                    {
                        TestContext.Out.WriteLine($"Could not take '{installed.Subject}' out of {Location}\\CA:{e.Message}");
                    }
                    finally
                    {
                        installed.Dispose();
                    }
                }

        }

        #endregion

    }

}
