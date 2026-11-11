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
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

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
    /// the node's commands with the meter's prompt, a command of the meter's
    /// own found without being listed, and the same command line for whoever
    /// signs in over SSH, whichever program hosts the meter.
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
