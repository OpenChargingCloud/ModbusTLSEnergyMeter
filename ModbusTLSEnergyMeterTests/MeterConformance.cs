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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What every node has to answer, asked of an energy meter - the
    /// conformance suite of WWCP_Node_TestKit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The sign-in, the configuration, name resolution and the time servers,
    /// the diagnostics, the log and its event stream, stopping with browsers
    /// watching, the certificate store and the web interface. What is left of
    /// this suite's own copies is what only a meter says: its readings and
    /// its signed values, its roles and its accounts, its listeners and the
    /// certificates they show, its log book and its counters.
    /// </para>
    /// <para>
    /// A meter signs in where every node's pages do, and so where the suite
    /// signs in by itself. It is not made without a key infrastructure: the
    /// certificate its Modbus/TLS listener shows and the CA its clients are
    /// issued by. That is made once for the fixture, because a meter only
    /// reads it into a store of its own, in the directory of its test.
    /// </para>
    /// </remarks>
    public class MeterConformance : NodeConformanceTests
    {

        #region Data

        /// <summary>
        /// The key infrastructure every meter of this fixture is started with.
        /// </summary>
        private String pki = default!;

        #endregion


        #region OneTimeSetUp / OneTimeTearDown

        [OneTimeSetUp]
        public async Task MakeTheKeyInfrastructure()
        {

            pki = Path.Combine(Path.GetTempPath(), $"meter-conformance-pki-{Guid.NewGuid().ToString("N")[..12]}");

            await new ModbusPKI().BuildPKI(pki);

        }

        [OneTimeTearDown]
        public void RemoveTheKeyInfrastructure()
        {

            try
            {
                if (pki is not null && System.IO.Directory.Exists(pki))
                    System.IO.Directory.Delete(pki, true);
            }
            catch (IOException)
            { }
            catch (UnauthorizedAccessException)
            { }

        }

        #endregion


        #region (protected override) NewNode(Directory, Configuration)

        protected override WWCPNode NewNode(String   Directory,
                                            JObject  Configuration)
        {

            var configuration = Path.Combine(Directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, Configuration.ToString());

            return new ModbusTLSEnergyMeter(
                       SerialNumber:       "meter-conformance",
                       ServerPfxPath:      Path.Combine(pki, "server.pfx"),
                       ServerPfxPassword:  "demo",
                       ClientCACertPath:   Path.Combine(pki, "issuing-clients-ca.crt"),
                       ListenAddress:      NetIPAddress.Loopback,
                       ListenPort:         TestPorts.Free(),
                       HTTPHostname:       IPv4Address.Localhost,
                       HTTPPort:           IPPort.Parse(TestPorts.Free()),
                       DataPath:           Path.Combine(Directory, "data"),
                       ConfigFile:         new WWCPConfigFile(configuration),
                       LogKeepDays:        0,
                       LogToConsole:       false,
                       BridgeDebugLog:     false
                   );

        }

        #endregion

    }

}
