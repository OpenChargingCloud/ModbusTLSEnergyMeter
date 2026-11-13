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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The meter's command line, which is the library's and not the program's:
    /// the node's commands with the meter's prompt, the meter's own - what it
    /// measures, who is connected over Modbus/TLS, and its registers read and
    /// written - a command of the meter's found without being listed, and the
    /// same command line for whoever signs in over SSH, whichever program
    /// hosts the meter.
    /// </summary>
    /// <remarks>
    /// A meter that is made and not started: a command line is built from the
    /// meter's properties, and asks none of its ports.
    /// </remarks>
    [TestFixture]
    public class MeterCLITests
    {

        #region Data

        private const String           SerialNumber  = "meter-cli-001";

        private ModbusTLSEnergyMeter?  meter;
        private String?                workingDirectory;
        private String?                pkiDirectory;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            workingDirectory = Path.Combine(
                                   Path.GetTempPath(),
                                   "ModbusTLSEnergyMeterTests",
                                   Guid.NewGuid().ToString("N")
                               );

            Directory.CreateDirectory(workingDirectory);

            pkiDirectory = Path.Combine(workingDirectory, "pki");

            await new ModbusPKI().BuildPKI(pkiDirectory);

            meter = new ModbusTLSEnergyMeter(
                        SerialNumber:       SerialNumber,
                        ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                        ServerPfxPassword:  "demo",
                        ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                        ListenAddress:      NetIPAddress.Loopback,
                        ListenPort:         TestPorts.Free(),
                        HTTPHostname:       IPv4Address.Localhost,
                        HTTPPort:           IPPort.Parse(TestPorts.Free()),
                        DataPath:           Path.Combine(workingDirectory, "data"),
                        ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory, "configuration.json")),
                        LogKeepDays:        0,
                        LogToConsole:       false
                    );

        }

        [TearDown]
        public async Task TearDown()
        {

            if (meter is not null)
                await meter.DisposeAsync();

            meter = null;

            TestAuthorities.RemoveInstalled(pkiDirectory);

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file the meter still holds is not what is under test */ }
            }

        }

        #endregion


        #region TheMetersCommandLineHasTheNodesCommands()

        /// <summary>
        /// syncNTS, which the meter had a copy of before it was the node's, once;
        /// and Styx's own - help and quit - beside it.
        /// </summary>
        [Test]
        public async Task TheMetersCommandLineHasTheNodesCommands()
        {

            using var cli = new MeterCLI(meter!);

            Assert.Multiple(() => {
                Assert.That(cli.Meter,                                       Is.SameAs(meter));
                Assert.That(cli.Commands.OfType<SyncNTSCommand>().Count(),  Is.EqualTo(1), "the node's command, once");
                Assert.That(cli.Commands.Select(command => command.GetType().Name),
                            Does.Contain("HelpCommand").And.Contain("QuitCommand"));
            });

            Assert.That(String.Join(" | ", await cli.Execute("help")), Does.Contain("syncNTS"));

        }

        #endregion

        #region ThePromptIsTheMetersSerialNumber()

        /// <summary>
        /// The prompt says which of the meters on a bench this is, by the serial
        /// number everything else about it says as well.
        /// </summary>
        [Test]
        public void ThePromptIsTheMetersSerialNumber()
        {

            using var cli = new PromptOf(meter!);

            Assert.That(cli.Prompt, Is.EqualTo($"{SerialNumber}> "));

        }

        #endregion

        #region ACommandOfTheMetersOwnIsFoundWithoutBeingListed()

        /// <summary>
        /// A command built from a MeterCLI is found by walking its assembly, and
        /// answers with what it reaches through the meter - a new command of the
        /// meter's is a new file and nothing else. A node's command line, which
        /// cannot build it, does not have it.
        /// </summary>
        /// <remarks>
        /// The meter has no command of its own yet; this one lives in the tests,
        /// whose assembly is walked as MeterCLI's constructor walks the
        /// library's - RegisterCLIType(typeof(MeterCLI)) is this call for the
        /// assembly MeterCLI is in. The assemblies a constructor is given are
        /// walked for commands built from nothing or from a plain CLI only, so
        /// a command built from a MeterCLI belongs in the library.
        /// </remarks>
        [Test]
        public async Task ACommandOfTheMetersOwnIsFoundWithoutBeingListed()
        {

            using var cli      = new MeterCLI(meter!);
            using var nodeCLI  = new NodeCLI (meter!);

            cli.    RegisterAssemblies(typeof(MeterCLI), typeof(MeterOnlyCommand).Assembly);
            nodeCLI.RegisterAssemblies(typeof(NodeCLI),  typeof(MeterOnlyCommand).Assembly);

            Assert.Multiple(() => {
                Assert.That(cli.    Commands.OfType<MeterOnlyCommand>().Count(),  Is.EqualTo(1), "the meter's own, once");
                Assert.That(cli.    Commands.OfType<SyncNTSCommand>().  Count(),  Is.EqualTo(1), "the node's, still once");
                Assert.That(nodeCLI.Commands.OfType<MeterOnlyCommand>(),          Is.Empty,      "not a node's");
            });

            Assert.That(await cli.Execute(MeterOnlyCommand.CommandName), Is.EqualTo(new[] { SerialNumber }));

        }

        #endregion

        #region OverSSHTheMeterHasItsOwnCommandLine()

        /// <summary>
        /// Whoever signs in over SSH gets the meter's command line, without the
        /// program that hosts the meter having to say so: a test, a service or
        /// another program hosts a meter without ModbusTLSEnergyMeterCLI.
        /// </summary>
        [Test]
        public async Task OverSSHTheMeterHasItsOwnCommandLine()
        {

            Assert.That(meter!.CommandLines, Is.Not.Null, "a session over SSH would get the node's command line only");

            await using var terminal  = new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask);
            using       var cli       = meter.CommandLines!(terminal, CLICaller.Console);

            Assert.That(cli, Is.InstanceOf<MeterCLI>());

            Assert.Multiple(() => {
                Assert.That(((MeterCLI) cli).Meter,                          Is.SameAs(meter));
                Assert.That(cli.Commands.OfType<SyncNTSCommand>().Count(),  Is.EqualTo(1));
            });

        }

        #endregion


        #region TheMeterHasCommandsOfItsOwn()

        /// <summary>
        /// What the meter measures, who is connected to it over Modbus/TLS,
        /// and its registers read and written: each once, and in the help.
        /// </summary>
        [Test]
        public async Task TheMeterHasCommandsOfItsOwn()
        {

            using var cli = new MeterCLI(meter!);

            Assert.Multiple(() => {
                Assert.That(cli.Commands.OfType<ShowMeterValuesCommand>().Count(),  Is.EqualTo(1));
                Assert.That(cli.Commands.OfType<ShowConnectionsCommand>().Count(),  Is.EqualTo(1));
                Assert.That(cli.Commands.OfType<ReadRegistersCommand>  ().Count(),  Is.EqualTo(1));
                Assert.That(cli.Commands.OfType<WriteRegistersCommand> ().Count(),  Is.EqualTo(1));
            });

            Assert.That(String.Join(" | ", await cli.Execute("help")),
                        Does.Contain("showMeterValues").
                         And.Contain("showConnections").
                         And.Contain("readRegisters").
                         And.Contain("writeRegisters"));

        }

        #endregion

        #region ShowMeterValues_SaysWhatTheMeterMeasures()

        /// <summary>
        /// Who the meter is, the three phases and their total, the frequency
        /// and both energy counters - as numbers with a point, whatever the
        /// language of the machine.
        /// </summary>
        [Test]
        public async Task ShowMeterValues_SaysWhatTheMeterMeasures()
        {

            using var cli = new MeterCLI(meter!);

            var said = await cli.Execute("showMeterValues");
            var text = String.Join("\n", said);

            Assert.Multiple(() => {

                Assert.That(said[0],  Does.Contain($"serial number {SerialNumber}"));

                Assert.That(said.Count(line => line.StartsWith("L1") || line.StartsWith("L2") || line.StartsWith("L3") || line.StartsWith("total")),
                            Is.EqualTo(4), text);

                Assert.That(said.Where(line => line.StartsWith('L')),
                            Has.All.Matches<String>(line => line is not null && line.Contains(" V ") && line.Contains(" A ") && line.EndsWith(" W")));

                // Around 50 Hz, as a grid is: 49.96 as much as 50.02.
                Assert.That(text,     Does.Match(@"Frequency  (49|50)(\.\d{1,3})? Hz"));
                Assert.That(text,     Does.Match(@"Imported   \d+(\.\d+)? Wh"));
                Assert.That(text,     Does.Match(@"Exported   \d+(\.\d+)? Wh"));

                Assert.That(String.Join("\n", said.Skip(1)), Does.Not.Contain(","),
                            "a number with a comma is the machine's language, not the meter's");

                Assert.That(text,     Does.Not.Match(@"\d\.\d{5,}"),
                            "230.9 V, and not what a binary fraction is when it is asked for all its digits");

            });

        }

        #endregion

        #region ReadRegisters_ReadsWhatAModbusClientWouldRead()

        /// <summary>
        /// The registers as a client reads them, with what they are as text
        /// where they are text - the device's, and the session model's behind
        /// them; a register there is none of is the Modbus exception a client
        /// would be answered, and what is no address is said to be none.
        /// </summary>
        [Test]
        public async Task ReadRegisters_ReadsWhatAModbusClientWouldRead()
        {

            using var cli = new MeterCLI(meter!);

            var marker   = await cli.Execute($"readRegisters {SunSpecMeterMap.BaseAddress} 2");
            var inHex    = await cli.Execute($"readRegisters 0x{SunSpecMeterMap.BaseAddress:X4}");
            var sessions = await cli.Execute($"readRegisters {meter!.SessionModelFactory!.ModelAddress} 2");
            var nowhere  = await cli.Execute("readRegisters 1 4");

            Assert.Multiple(() => {

                Assert.That(marker,       Has.Length.EqualTo(2));
                Assert.That(marker[0],    Does.StartWith($"{SunSpecMeterMap.BaseAddress}  0x5375").And.EndWith("\"Su\""));
                Assert.That(marker[1],    Does.StartWith($"{SunSpecMeterMap.BaseAddress + 1}  0x6E53").And.EndWith("\"nS\""));

                Assert.That(inHex,        Is.EqualTo(new[] { marker[0] }), "one register without a count, and the address in hexadecimal");

                Assert.That(sessions,     Has.Length.EqualTo(2), "the session model is behind the device's models, and is read like them");
                Assert.That(sessions[0],  Does.StartWith($"{meter.SessionModelFactory.ModelAddress}  0x"));

                Assert.That(nowhere,      Is.EqualTo(new[] { $"Registers 1..4 was answered with {ModbusExceptionCode.IllegalDataAddress}." }));

            });

            Assert.That((await cli.Execute("readRegisters"))          [0],  Does.StartWith("Usage: readRegisters <address> [<count>]"));
            Assert.That((await cli.Execute("readRegisters forty"))    [0],  Does.Contain("'forty' is no register address"));
            Assert.That((await cli.Execute("readRegisters 70000"))    [0],  Does.Contain("'70000' is no register address"));
            Assert.That((await cli.Execute("readRegisters 40000 0"))  [0],  Does.Contain("'0' is no count of registers"));
            Assert.That((await cli.Execute("readRegisters 40000 126"))[0],  Does.Contain("'126' is no count of registers"));
            Assert.That((await cli.Execute("readRegisters 65535 2"))  [0],  Does.Contain("ends behind the last register"));

        }

        #endregion

        #region WriteRegisters_WritesAsAModbusClientAndIntoTheLogBook()

        /// <summary>
        /// A register written is written - the meter mode is the meter's mode
        /// from then on - and is in the log book with who wrote it; one that
        /// cannot be written is the Modbus exception a client would be
        /// answered, changes nothing, and is in the log book as well.
        /// </summary>
        [Test]
        public async Task WriteRegisters_WritesAsAModbusClientAndIntoTheLogBook()
        {

            using var cli = new MeterCLI(meter!);

            var mode    = SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterMeterMode);
            var serial  = SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonSN);

            Assert.That(meter!.Device.Mode, Is.EqualTo(SunSpecMeterMode.Net));

            var written = await cli.Execute($"writeRegisters {mode} {(UInt16) SunSpecMeterMode.ImportOnly}");

            Assert.Multiple(() => {
                Assert.That(written,            Is.EqualTo(new[] { $"Register {mode} written: 0x{(UInt16) SunSpecMeterMode.ImportOnly:X4}." }));
                Assert.That(meter.Device.Mode,  Is.EqualTo(SunSpecMeterMode.ImportOnly));
            });

            var refused = await cli.Execute($"writeRegisters {serial} 0x4142 0x4344");

            Assert.That(refused[0],
                        Does.StartWith($"Registers {serial}..{serial + 1} was answered with ").And.EndWith(": nothing was written."));

            Assert.That((await cli.Execute("showMeterValues"))[0],
                        Does.Contain($"serial number {SerialNumber}"));

            var logBook = meter.Log.Recent(200, Tag: "write").ToArray();

            Assert.Multiple(() => {

                Assert.That(logBook,  Has.Length.EqualTo(2));
                Assert.That(logBook,  Has.All.Matches<LogEntry>(entry => entry is { Metrological: true }), "a write is evidence, and belongs in the log book");

                Assert.That(logBook.Select(entry => entry.Message),
                            Has.Some.EqualTo($"Somebody at the command line wrote 0x{(UInt16) SunSpecMeterMode.ImportOnly:X4} to register {mode}."));

                Assert.That(logBook.Select(entry => entry.Message),
                            Has.Some.StartWith($"Somebody at the command line wrote 0x4142 0x4344 to registers {serial}..{serial + 1}, which was answered with "));

            });

            Assert.That((await cli.Execute("writeRegisters"))              [0],  Does.StartWith("Usage: writeRegisters <address> <value> [<value> ...]"));
            Assert.That((await cli.Execute($"writeRegisters {mode}"))      [0],  Does.StartWith("Usage: writeRegisters"));
            Assert.That((await cli.Execute("writeRegisters there 1"))      [0],  Does.Contain("'there' is no register address"));
            Assert.That((await cli.Execute($"writeRegisters {mode} much")) [0],  Does.Contain("'much' is no value of a register"));
            Assert.That((await cli.Execute($"writeRegisters {mode} 65536"))[0],  Does.Contain("'65536' is no value of a register"));
            Assert.That((await cli.Execute("writeRegisters 65535 1 2"))    [0],  Does.Contain("ends behind the last register"));

            Assert.That(meter.Log.Recent(200, Tag: "write").Count(), Is.EqualTo(2), "what was not understood wrote nothing, and is no entry");

        }

        #endregion

        #region AValueOfARegister_IsUnsignedHexadecimalOrNegative(Text, Value)

        /// <summary>
        /// What somebody types for a register: the number, the number in
        /// hexadecimal, or a negative number as its sixteen bits.
        /// </summary>
        [TestCase("0",       0)]
        [TestCase("65535",   65535)]
        [TestCase("0xCAFE",  0xCAFE)]
        [TestCase("0Xcafe",  0xCAFE)]
        [TestCase("-1",      0xFFFF)]
        [TestCase("-32768",  0x8000)]
        public void AValueOfARegister_IsUnsignedHexadecimalOrNegative(String Text, Int32 Value)
        {

            Assert.That(WriteRegistersCommand.TryParseValue(Text, out var value), Is.True);
            Assert.That((Int32) value,                                            Is.EqualTo(Value));

        }

        /// <summary>
        /// And what is none of these is no value.
        /// </summary>
        [TestCase("")]
        [TestCase("65536")]
        [TestCase("-32769")]
        [TestCase("0x10000")]
        [TestCase("+1")]
        [TestCase("1.5")]
        [TestCase("1 000")]
        public void WhatIsNoValueOfARegister_IsNone(String Text)
        {
            Assert.That(WriteRegistersCommand.TryParseValue(Text, out _), Is.False);
        }

        #endregion

        #region ShowConnections_SaysWhoIsConnectedOverModbusTLS()

        /// <summary>
        /// Nobody, while nobody is; a connection with the SunSpec role in its
        /// certificate, where it comes from and what it asked - a request that
        /// was refused among them - while it is open; and nobody again once it
        /// is closed.
        /// </summary>
        [Test]
        public async Task ShowConnections_SaysWhoIsConnectedOverModbusTLS()
        {

            await using var started = await TestPorts.StartedOnFreshPorts(() => new ModbusTLSEnergyMeter(
                                          SerialNumber:       "meter-cli-connections",
                                          ServerPfxPath:      Path.Combine(pkiDirectory!, "server.pfx"),
                                          ServerPfxPassword:  "demo",
                                          ClientCACertPath:   Path.Combine(pkiDirectory!, "issuing-clients-ca.crt"),
                                          ListenAddress:      NetIPAddress.Loopback,
                                          ListenPort:         TestPorts.Free(),
                                          HTTPHostname:       IPv4Address.Localhost,
                                          HTTPPort:           IPPort.Parse(TestPorts.Free()),
                                          DataPath:           Path.Combine(workingDirectory!, "data-connections"),
                                          ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory!, "configuration-connections.json")),
                                          LogKeepDays:        0,
                                          LogToConsole:       false
                                      ));

            using var cli = new MeterCLI(started);

            Assert.That(await cli.Execute("showConnections"), Is.EqualTo(new[] { "Nobody is connected to this meter over Modbus/TLS." }));

            using (var reader = await SessionModelTests.TLSConnection.Open(started.ListenPort, pkiDirectory!, SunSpecRoles.ReadOnly))
            {

                // Known once its TLS handshake held - which the meter learns
                // a moment after the client does - and where it comes from
                // with its first request.
                for (var attempt = 0; attempt < 50 && started.ModbusConnections.Count == 0; attempt++)
                    await Task.Delay(100);

                var said = await cli.Execute("showConnections");

                Assert.That(said,     Has.Length.EqualTo(1));
                Assert.That(said[0],  Does.StartWith("#1  ").
                                       And.Contain(SunSpecRoles.ReadOnly).
                                       And.Contain("from a peer that has asked nothing yet").
                                       And.EndWith("no request"));

                Assert.That(await reader.Write(SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterMeterMode), [ 1 ]),
                            Is.EqualTo(ModbusExceptionCode.IllegalFunction), "a role that reads may not write");

                said = await cli.Execute("showConnections");

                Assert.Multiple(() => {

                    Assert.That(said,                               Has.Length.EqualTo(1));
                    Assert.That(said[0],                            Does.Contain("from 127.0.0.1:").And.Contain("1 request (1 refused), the last at "));

                    Assert.That(started.ModbusConnections,          Has.Count.EqualTo(1));
                    Assert.That(started.ModbusConnections[0].Role,  Is.EqualTo(SunSpecRoles.ReadOnly));
                    Assert.That(started.Device.Mode,                Is.EqualTo(SunSpecMeterMode.Net));

                });

            }

            for (var attempt = 0; attempt < 100 && started.ModbusConnections.Count > 0; attempt++)
                await Task.Delay(100);

            Assert.That(await cli.Execute("showConnections"), Is.EqualTo(new[] { "Nobody is connected to this meter over Modbus/TLS." }),
                        "a connection that was closed is no longer one");

        }

        #endregion

        #region OverSSH_ARoleMayTypeWhatItMayDoOnTheWebInterface()

        /// <summary>
        /// What the web interface asks of an account, the command line asks of
        /// it over SSH: a guest reads what the meter measures and its
        /// registers, and neither sees who is connected nor writes; a viewer
        /// and the support see who is connected, and do not write either.
        /// What was refused wrote nothing.
        /// </summary>
        /// <remarks>
        /// A meter that was started: the groups the roles are, are made at
        /// its start.
        /// </remarks>
        [Test]
        public async Task OverSSH_ARoleMayTypeWhatItMayDoOnTheWebInterface()
        {

            await using var started = await TestPorts.StartedOnFreshPorts(() => new ModbusTLSEnergyMeter(
                                          SerialNumber:       "meter-cli-roles",
                                          ServerPfxPath:      Path.Combine(pkiDirectory!, "server.pfx"),
                                          ServerPfxPassword:  "demo",
                                          ClientCACertPath:   Path.Combine(pkiDirectory!, "issuing-clients-ca.crt"),
                                          ListenAddress:      NetIPAddress.Loopback,
                                          ListenPort:         TestPorts.Free(),
                                          HTTPHostname:       IPv4Address.Localhost,
                                          HTTPPort:           IPPort.Parse(TestPorts.Free()),
                                          DataPath:           Path.Combine(workingDirectory!, "data-roles"),
                                          ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory!, "configuration-roles.json")),
                                          LogKeepDays:        0,
                                          LogToConsole:       false
                                      ));

            var meter = started;
            var mode  = SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterMeterMode);

            await using var terminal = new VT100Terminal((bytes, cancellationToken) => ValueTask.CompletedTask);

            using var guest   = new MeterCLI(meter, terminal, await OverSSHAs(meter, "gwen", MeterAccess.Guest));
            using var viewer  = new MeterCLI(meter, terminal, await OverSSHAs(meter, "vera", MeterAccess.Viewer));
            using var support = new MeterCLI(meter, terminal, await OverSSHAs(meter, "sally", MeterAccess.Support));

            Assert.That((await guest. Execute("showMeterValues"))          [0],  Does.Contain("serial number meter-cli-roles"));
            Assert.That((await guest. Execute($"readRegisters {mode}"))    [0],  Does.StartWith($"{mode}  0x0000"));
            Assert.That((await guest. Execute("showConnections"))          [0],  Is.EqualTo("'gwen' may not do that here: it needs the viewer or support or auditor or systemadmin role."));
            Assert.That((await guest. Execute($"writeRegisters {mode} 1")) [0],  Is.EqualTo("'gwen' may not do that here: it needs the systemadmin role."));

            Assert.That((await viewer.Execute("showConnections"))          [0],  Does.StartWith("Nobody is connected"));
            Assert.That((await viewer.Execute($"writeRegisters {mode} 1")) [0],  Is.EqualTo("'vera' may not do that here: it needs the systemadmin role."));

            // What the meter's support is for: what is going on, and no more.
            Assert.That((await support.Execute("showMeterValues"))         [0],  Does.Contain("serial number meter-cli-roles"));
            Assert.That((await support.Execute($"readRegisters {mode}"))   [0],  Does.StartWith($"{mode}  0x0000"));
            Assert.That((await support.Execute("showConnections"))         [0],  Does.StartWith("Nobody is connected"));
            Assert.That((await support.Execute($"writeRegisters {mode} 1"))[0],  Is.EqualTo("'sally' may not do that here: it needs the systemadmin role."));

            Assert.Multiple(() => {

                Assert.That(meter.Device.Mode,                    Is.EqualTo(SunSpecMeterMode.Net));
                Assert.That(meter.Log.Recent(200, Tag: "write"),  Is.Empty);

                Assert.That(meter.Log.Recent(200, Tag: "auth").Select(entry => entry.Message),
                            Has.Some.Contains("'gwen' was refused meter:edit on 'writeRegisters' at the command line over SSH"));

            });

        }

        /// <summary>
        /// An account in the group of a role, as it types at the meter's
        /// command line over SSH.
        /// </summary>
        private static async Task<CLICaller> OverSSHAs(ModbusTLSEnergyMeter Meter, String UserId, Role Role)
        {

            var api   = Meter.ExtAPI;

            var user  = new User(
                            User_Id.Parse(UserId),
                            I18NString.Create(UserId),
                            SimpleEMailAddress.Parse($"{UserId}@example.test"),
                            IsAuthenticated:  true,
                            DataSource:       "test"
                        );

            await api.AddUser(user, SkipNewUserEMail: true, SkipNewUserNotifications: true);

            Assert.That(api.TryGetUserGroup(Role.GroupId, out var group) && group is UserGroup, Is.True,
                        $"There is no {Role.Name} group.");

            var joined = await api.AddUserToUserGroup(user, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!);

            Assert.That(joined.IsSuccess, Is.True,
                        $"'{UserId}' could not be put in the {Role.Name} group: {joined}");

            return new CLICaller(
                       user,
                       new SshSessionInfo(
                           $"test-{UserId}",
                           UserId,
                           "publickey",
                           null,
                           null,
                           null,
                           null,
                           SshSessionRestrictions.None
                       )
                   );

        }

        #endregion


        #region (class) PromptOf

        /// <summary>
        /// The meter's command line, with the prompt it writes in front of every
        /// line said out loud.
        /// </summary>
        private sealed class PromptOf(ModbusTLSEnergyMeter Meter) : MeterCLI(Meter)
        {
            public String Prompt
                => GetPrompt();
        }

        #endregion

        #region (class) MeterOnlyCommand

        /// <summary>
        /// A command only a meter has: its serial number, reached through the
        /// meter of the command line it was built from.
        /// </summary>
        public class MeterOnlyCommand(MeterCLI CLI) : ACLICommand<MeterCLI>(CLI),
                                                      ICLICommand
        {

            public static readonly String CommandName = "meterOnly";

            public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

                => Arguments.Length == 1 && CommandName.StartsWith(Arguments[0], StringComparison.CurrentCultureIgnoreCase)
                       ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                       : [];

            public override Task<String[]> Execute(String[]           Arguments,
                                                   CancellationToken  CancellationToken)

                => Task.FromResult<String[]>([ cli.Meter.SerialNumber ]);

            public override String Help()
                => $"{CommandName} - a command only a meter has";

        }

        #endregion

    }

}
