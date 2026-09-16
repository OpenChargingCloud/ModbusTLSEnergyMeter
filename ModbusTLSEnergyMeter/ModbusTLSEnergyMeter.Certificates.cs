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

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// How often the certificate stores are asked whether what they would
        /// hand out has changed.
        /// </summary>
        /// <remarks>
        /// The rollover itself does not depend on this: both listeners ask the
        /// store at every handshake, so a certificate that becomes valid at
        /// 03:00 is shown to the first peer that connects at 03:00. This is so
        /// that it also gets written down at 03:00 rather than whenever the
        /// next peer happens to turn up, which on a quiet meter could be the
        /// following afternoon.
        /// </remarks>
        public static readonly TimeSpan DefaultCertificateCheckEvery = TimeSpan.FromMinutes(1);

        /// <summary>
        /// How close to running out a certificate has to be before this meter
        /// starts saying so.
        /// </summary>
        public static readonly TimeSpan CertificateExpiryWarning     = TimeSpan.FromDays(21);

        #endregion

        #region (private) StartWatchingTheCertificates()

        /// <summary>
        /// Begin noticing when a certificate takes over, runs out, or is about
        /// to.
        /// </summary>
        private void StartWatchingTheCertificates()
        {

            certificateTimer?.Dispose();

            certificateTimer = TimeProvider.CreateTimer(
                                   _ => CheckTheCertificates(),
                                   null,
                                   DefaultCertificateCheckEvery,
                                   DefaultCertificateCheckEvery
                               );

            foreach (var store in new[] { modbusCertificates, webCertificates })
            {

                var current = store.Current;

                if (current?.Certificate is not null)
                    Log.Info(
                        $"The {store.Purpose} listener shows '{current.Certificate.Subject}', valid until {current.Certificate.NotAfter:yyyy-MM-dd}.",
                        "certificates", store.Purpose
                    );

                else if (store.Purpose == "modbus" || HTTPSEnabled)
                    Log.Warning(
                        $"There is no valid {store.Purpose} certificate: every handshake on that listener will fail.",
                        "certificates", store.Purpose
                    );

                if (store.Next?.Certificate is not null)
                    Log.Info(
                        $"A newer {store.Purpose} certificate takes over on {store.Next.Certificate.NotBefore:yyyy-MM-dd HH:mm}.",
                        "certificates", store.Purpose
                    );

            }

        }

        #endregion

        #region (private) CheckTheCertificates()

        /// <summary>
        /// Let each store work out again what it would hand out - which is
        /// what raises the line about a rollover - and grumble about anything
        /// that is running out.
        /// </summary>
        private void CheckTheCertificates()
        {

            var now = TimeProvider.GetUtcNow();

            foreach (var store in new[] { modbusCertificates, webCertificates })
            {

                try
                {

                    store.CheckRollover();

                    var current = store.Current;

                    // Only worth saying when nothing else is lined up to take
                    // over: a certificate running out next week with its
                    // successor already in the store is not a problem, it is
                    // the arrangement working.
                    if (current?.Certificate is not null &&
                        store.Next is null &&
                        current.Certificate.NotAfter - now < CertificateExpiryWarning)
                    {
                        Log.Warning(
                            $"The {store.Purpose} certificate runs out on {current.Certificate.NotAfter:yyyy-MM-dd} and nothing has been put in to follow it.",
                            "certificates", store.Purpose
                        );
                    }

                }
                catch (Exception e)
                {
                    Log.Warning($"The {store.Purpose} certificates could not be checked: {e.Message}", "certificates", store.Purpose);
                }

            }

        }

        #endregion

        #region CertificateStoreFor(Purpose)

        /// <summary>
        /// The store a request names, or null when it names neither.
        /// </summary>
        public CertificateStore? CertificateStoreFor(String? Purpose)

            => Purpose?.Trim().ToLowerInvariant() switch {
                   "modbus"  => modbusCertificates,
                   "web"     => webCertificates,
                   _         => null
               };

        #endregion

    }

}
