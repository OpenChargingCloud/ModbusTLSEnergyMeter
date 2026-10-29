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

using cloud.charging.open.protocols.WWCP.Node;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// The PKI a meter builds for itself at its first start, in the directory
    /// given by --pki: a CA, two issuing CAs, the meter's certificate and one
    /// client per role - and the private keys of every one of them.
    /// </summary>
    /// <remarks>
    /// Hermod's ModbusPKI writes them as any file is written: on Unix 0644 in a
    /// directory of 0755, so that every user of the machine could read the
    /// CA's key and issue themselves a client of any role. Everything else the
    /// meter keeps - the accounts, the logs, the certificate store, the SSH
    /// host key - is its owner's alone since WWCP_Node 829896d, what is in
    /// it as well since 1a8db65; the PKI is given the same with
    /// <see cref="OwnerOnly"/>: on Unix the directory 0700 and every file in
    /// it 0600, on Windows the protected access control list of the account,
    /// SYSTEM and the administrators, which everything in it inherits.
    /// </remarks>
    public static class BootstrapPKI
    {

        /// <summary>
        /// Keep everybody but its owner out of the given PKI directory and of
        /// everything in it - one just built, or one an older version built
        /// and left open, which is taken in at the next start. A directory
        /// that is not there - the certificates given from elsewhere - is not
        /// made.
        /// </summary>
        /// <param name="Directory">The PKI's directory.</param>
        /// <param name="Complain">Told what could not be restricted, and why.</param>
        public static void KeepToItsOwner(String           Directory,
                                          Action<String>?  Complain   = null)
        {

            if (!System.IO.Directory.Exists(Directory))
                return;

            OwnerOnly.Directory(Directory, Complain);

        }

    }

}
