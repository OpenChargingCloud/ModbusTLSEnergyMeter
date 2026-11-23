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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Modbus;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.EnergyMeters.ModbusTLS.MeterReaders;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What reads the meter over Modbus without Modbus/TLS - over the SSH
    /// subsystem "modbus@open.charging.cloud" or a WebSocket of the subprotocol
    /// "modbus" - is decided by the SunSpec role of the group of its login, at
    /// every request, as a client certificate's role decides over Modbus/TLS.
    /// </summary>
    [TestFixture]
    public class MeterReadersTests
    {

        #region Data

        private const UInt16           MeterMode  = 40094;

        private String                 directory  = "";
        private ModbusTLSEnergyMeter?  meter;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public async Task SetUp()
        {

            directory = Path.Combine(Path.GetTempPath(), "meter-readers-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, new JObject(
                new JProperty("nts",              new JObject(new JProperty("groups", new JObject(new JProperty("legal", new JObject(new JProperty("enabled", false))))))),
                new JProperty("webSocketServer",  new JObject(
                    new JProperty("enabled",               true),
                    new JProperty("address",               "127.0.0.1"),
                    new JProperty("port",                  TestPorts.Free().ToUInt16()),
                    new JProperty("clientAuthentication",  new JArray("httpAuthWithoutTLS")),
                    new JProperty("ssh",                   new JObject(new JProperty("enabled", true)))
                )),
                new JProperty("ssh",              new JObject(
                    new JProperty("enabled",  true),
                    new JProperty("port",     TestPorts.Free().ToUInt16())
                ))
            ).ToString());

            var (serverPfx, clientCA) = ModbusTLSFiles(directory);

            meter = new ModbusTLSEnergyMeter(
                        SerialNumber:       "meter-readers",
                        ServerPfxPath:      serverPfx,
                        ServerPfxPassword:  "test",
                        ClientCACertPath:   clientCA,
                        ListenAddress:      NetIPAddress.Loopback,
                        ListenPort:         TestPorts.Free(),
                        HTTPHostname:       IPv4Address.Localhost,
                        HTTPPort:           TestPorts.Free(),
                        DataPath:           directory,
                        ConfigFile:         new WWCPConfigFile(configuration),
                        LogKeepDays:        0,
                        LogToConsole:       false,
                        BridgeDebugLog:     false
                    );

            await meter.Start();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (meter is not null)
            {
                await meter.Stop();
                await meter.DisposeAsync();
            }

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch
            { }

        }

        #endregion


        #region (private static) ModbusTLSFiles(Directory)

        /// <summary>
        /// A certificate for 127.0.0.1 and the CA that issued it, for the
        /// Modbus/TLS port this test does not speak to.
        /// </summary>
        private static (String ServerPfx, String ClientCA) ModbusTLSFiles(String Directory)
        {

            using var caKey      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var caRequest        = new CertificateRequest($"CN=The CA of a meter readers test {Guid.NewGuid()}", caKey, HashAlgorithmName.SHA256);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var ca         = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            using var serverKey  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var serverRequest    = new CertificateRequest("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using var server     = serverRequest.Create(ca.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey),
                                                        DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(29), Guid.NewGuid().ToByteArray());
            using var withKey    = server.CopyWithPrivateKey(serverKey);

            var serverPfx        = Path.Combine(Directory, "server.pfx");
            var clientCA         = Path.Combine(Directory, "clients-ca.crt");

            File.WriteAllBytes(serverPfx, withKey.Export(X509ContentType.Pkcs12, "test"));
            File.WriteAllText (clientCA,  ca.ExportCertificatePem());

            return (serverPfx, clientCA);

        }

        #endregion

        #region (private) AReader(Transport, Role, out Login, out Password)

        /// <summary>
        /// Something written down as what reads this meter, over SSH or over a
        /// WebSocket, with a password of its own, in the group of the given role
        /// or in the default group.
        /// </summary>
        private (User_Id Login, String Password) AReader(String   Transport,
                                                         String?  Role)
        {

            var login     = User_Id.Parse("reader-" + RandomExtensions.RandomString(8));
            var password  = RandomExtensions.RandomString(32);
            var url       = Transport == "ssh"
                                ? $"ssh://{login}@127.0.0.1:{meter!.SSHPort!.Value.ToUInt16()}"
                                : $"ws://127.0.0.1:{meter!.MeterReaderSettings.TCPPort!.Value.ToUInt16()}/{login}";

            Assert.That(meter.Connections.TryAddConnection(I18NString.Create("A reader"), URL.Parse(url), "MeterReader", true, null, null,
                                                           out _, out var error, Inbound: true),
                        Is.True, error);

            Assert.That(meter.WebSocketLogins.TrySetPasswordAuthentication(login, password, Role is null ? null : SunSpecLoginGroups.GroupOf(Role), null, out error),
                        Is.True, error);

            return (login, password);

        }

        #endregion

        #region (private) Connect(Transport, Login, Password)

        /// <summary>
        /// A Modbus client to this meter over SSH or over a WebSocket, signed in
        /// with the given password - and what to let go of afterwards.
        /// </summary>
        private async Task<(ModbusTCPClient Client, IAsyncDisposable Transport)> Connect(String   Transport,
                                                                                         User_Id  Login,
                                                                                         String   Password)
        {

            if (Transport == "ssh")
            {

                var ssh      = await SSHClient.Connect(
                                         "127.0.0.1",
                                         meter!.SSHPort!.Value,
                                         new SSHClientOptions {
                                             Username       = Login,
                                             Password       = Password,
                                             VerifyHostKey  = hostKey => true
                                         }
                                     );

                var channel  = await ssh.OpenSubsystem(ModbusWireNames.SshSubsystem);

                return (ModbusTCPClient.Over(channel.AsStream()), ssh);

            }

            var webSocket = new StreamWebSocketClient(
                                URL.Parse($"ws://127.0.0.1:{meter!.MeterReaderSettings.TCPPort!.Value.ToUInt16()}/{Login}"),
                                ModbusWireNames.Subprotocol,
                                HTTPBasicAuthentication.Create(Login.ToString(), Password),
                                null,
                                null,
                                null,
                                null,
                                null,
                                null
                            );

            var (_, response) = await webSocket.Connect();

            Assert.That(response.HTTPStatusCode, Is.EqualTo(HTTPStatusCode.SwitchingProtocols), "The WebSocket of Modbus was not opened.");
            Assert.That(response.SecWebSocketProtocol, Is.EqualTo(ModbusWireNames.Subprotocol));

            return (ModbusTCPClient.Over(webSocket.Stream), webSocket);

        }

        #endregion

        #region (private static) ExceptionOf(Request)

        private static async Task<ModbusExceptionCode?> ExceptionOf(Func<Task> Request)
        {
            try
            {
                await Request();
                return null;
            }
            catch (ModbusException e)
            {
                return e.Code;
            }
        }

        #endregion


        #region TheFourRoles_AreLoginGroups()

        /// <summary>
        /// The four SunSpec roles are login groups from the first start, named
        /// after them; any other group is no role.
        /// </summary>
        [Test]
        public void TheFourRoles_AreLoginGroups()
        {

            Assert.Multiple(() => {

                foreach (var role in SunSpecRoles.AllMandatory)
                {
                    Assert.That(meter!.WebSocketLogins.GetGroup(SunSpecLoginGroups.GroupOf(role))?.Name, Is.EqualTo(role));
                    Assert.That(SunSpecLoginGroups.RoleOf(SunSpecLoginGroups.GroupOf(role)),            Is.EqualTo(role));
                    Assert.That(SunSpecLoginGroups.RoleOf(role),                                        Is.EqualTo(role), "A group id is read whatever its case.");
                }

                Assert.That(SunSpecLoginGroups.RoleOf("default"),  Is.Null);
                Assert.That(SunSpecLoginGroups.RoleOf(null),       Is.Null);

            });

        }

        #endregion

        #region TheGroup_DecidesEveryRequest(Transport)

        /// <summary>
        /// A login of ReadOnly reads and may not write the meter mode; put into
        /// GridService it writes it at its next request, on the same connection;
        /// and the meter lists the connection with its transport, its login and
        /// the role of its last request.
        /// </summary>
        [TestCase("ssh")]
        [TestCase("ws")]
        public async Task TheGroup_DecidesEveryRequest(String Transport)
        {

            var (login, password)    = AReader(Transport, SunSpecRoles.ReadOnly);
            var (client, transport)  = await Connect(Transport, login, password);

            try
            {

                var mode    = (await client.ReadHoldingRegistersAsync(1, MeterMode, 1))[0];
                var before  = await ExceptionOf(() => client.WriteSingleRegisterAsync(1, MeterMode, mode));

                Assert.That(meter!.WebSocketLogins.TrySetGroup(login, SunSpecLoginGroups.GroupOf(SunSpecRoles.GridService), out var error), Is.True, error);

                var after   = await ExceptionOf(() => client.WriteSingleRegisterAsync(1, MeterMode, mode));

                var listed  = meter.ModbusConnections.FirstOrDefault(connection => connection.Login == login.ToString());

                Assert.Multiple(() => {
                    Assert.That(before,               Is.EqualTo(ModbusExceptionCode.IllegalFunction), "ReadOnly wrote the meter mode.");
                    Assert.That(after,                Is.Null,                                          "GridService did not write the meter mode.");
                    Assert.That(listed,               Is.Not.Null,                                      "The meter does not list the connection.");
                    Assert.That(listed?.Transport,    Is.EqualTo(Transport == "ssh" ? "SSH" : "WebSocket"));
                    Assert.That(listed?.Role,         Is.EqualTo(SunSpecRoles.GridService));
                    Assert.That(meter.MeterReadersIn, Does.Contain(login.ToString()));
                });

            }
            finally
            {
                await client.   DisposeAsync();
                await transport.DisposeAsync();
            }

        }

        #endregion

        #region WithoutARole_EverythingIsRefused(Transport)

        /// <summary>
        /// A login in the default group is let in, and answered with exception 01
        /// to everything.
        /// </summary>
        [TestCase("ssh")]
        [TestCase("ws")]
        public async Task WithoutARole_EverythingIsRefused(String Transport)
        {

            var (login, password)    = AReader(Transport, Role: null);
            var (client, transport)  = await Connect(Transport, login, password);

            try
            {
                Assert.That(await ExceptionOf(() => client.ReadHoldingRegistersAsync(1, 40000, 2)),
                            Is.EqualTo(ModbusExceptionCode.IllegalFunction));
            }
            finally
            {
                await client.   DisposeAsync();
                await transport.DisposeAsync();
            }

        }

        #endregion

        #region WhatIsNotWrittenDown_IsNotServed()

        /// <summary>
        /// A login of a role that is written down as nothing that reads this
        /// meter over SSH is not served Modbus there: its channel is closed.
        /// </summary>
        [Test]
        public async Task WhatIsNotWrittenDown_IsNotServed()
        {

            var login     = User_Id.Parse("stranger-" + RandomExtensions.RandomString(8));
            var password  = RandomExtensions.RandomString(32);

            Assert.That(meter!.WebSocketLogins.TrySetPasswordAuthentication(login, password, SunSpecLoginGroups.GroupOf(SunSpecRoles.SuperAdministrator), null, out var error),
                        Is.True, error);

            var (client, transport) = await Connect("ssh", login, password);

            try
            {
                Assert.That(async () => await client.ReadHoldingRegistersAsync(1, 40000, 2), Throws.InstanceOf<Exception>());
            }
            finally
            {
                await client.   DisposeAsync();
                await transport.DisposeAsync();
            }

        }

        #endregion

    }

}
