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

using System.Net.Sockets;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// A meter whose stopping fails: letting go of it says so - and lets go
    /// of it all the same: its Modbus/TLS port is closed, its timers no
    /// longer run, and its log file is no longer written.
    /// </summary>
    /// <remarks>
    /// What fails here is the meter's own part of stopping, before it has
    /// done any of it - the worst place for it to fail. Letting go of a meter
    /// used to stop at that failure, and kept the Modbus/TLS frontend
    /// listening, the meter's timers running and the node underneath it
    /// holding its log file; and since the meter counted as let go of, asking
    /// again changed nothing.
    /// </remarks>
    public class StopThatFailsTests
    {

        #region Data

        private String?                       workingDirectory;
        private String?                       pkiDirectory;
        private readonly List<FailingToStop>  made  = [];

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            workingDirectory = Path.Combine(
                                   Path.GetTempPath(),
                                   "ModbusTLSEnergyMeterTests",
                                   "stop-fails-" + Guid.NewGuid().ToString("N")[..12]
                               );

            Directory.CreateDirectory(workingDirectory);

            pkiDirectory = Path.Combine(workingDirectory, "pki");

            await new ModbusPKI().BuildPKI(pkiDirectory);

        }

        [TearDown]
        public async Task TearDown()
        {

            foreach (var meter in made)
            {
                try
                {
                    await meter.DisposeAsync();
                }
                catch (InvalidOperationException)
                {
                    // Its stopping fails; that is what it is for.
                }
            }

            made.Clear();

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file a meter let go of a moment too late is not what is under test */ }
            }

        }

        #endregion


        #region (helper) Started()

        /// <summary>
        /// A meter whose stopping fails, started on fresh ports, with a log
        /// file and timers it counts.
        /// </summary>
        private async Task<FailingToStop> Started()
        {

            var meter = await TestPorts.StartedOnFreshPorts(() => {

                var here = Path.Combine(workingDirectory!, Guid.NewGuid().ToString("N")[..8]);

                Directory.CreateDirectory(here);

                return new FailingToStop(
                           ServerPfxPath:     Path.Combine(pkiDirectory!, "server.pfx"),
                           ClientCACertPath:  Path.Combine(pkiDirectory!, "issuing-clients-ca.crt"),
                           ListenPort:        TestPorts.Free(),
                           HTTPPort:          IPPort.Parse(TestPorts.Free()),
                           DataPath:          Path.Combine(here, "data"),
                           ConfigFile:        new WWCPConfigFile(Path.Combine(here, WWCPConfigFile.DefaultFileName)),
                           Clock:             new CountedTimers()
                       );

            });

            made.Add(meter);

            return meter;

        }

        #endregion

        #region (helper) Refused(Port)

        /// <summary>
        /// Whether nothing listens on the given port of the loopback address.
        /// </summary>
        private static Boolean Refused(UInt16 Port)
        {

            using var client = new TcpClient();

            try
            {
                client.Connect(NetIPAddress.Loopback, Port);
                return false;
            }
            catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
            {
                return true;
            }

        }

        #endregion

        #region (helper) Read(File)

        /// <summary>
        /// What a log file says, read beside whoever may still be writing it.
        /// </summary>
        private static String Read(String File)
        {

            using var stream = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);

            return reader.ReadToEnd();

        }

        #endregion


        #region LettingGoOfAMeterWhoseStopFails_SaysSo_AndClosesItsModbusPort()

        /// <summary>
        /// The failure reaches whoever let go of the meter - and its Modbus/TLS
        /// port is closed all the same, as the node closes its web port.
        /// </summary>
        [Test]
        public async Task LettingGoOfAMeterWhoseStopFails_SaysSo_AndClosesItsModbusPort()
        {

            var meter  = await Started();
            var modbus = (UInt16) meter.ListenPort;
            var web    = meter.HTTPPort.ToUInt16();

            Assert.That(Refused(modbus), Is.False, "the meter did not listen for Modbus/TLS in the first place");

            Assert.That(async () => await meter.DisposeAsync(),
                        Throws.InstanceOf<InvalidOperationException>().With.Message.EqualTo(FailingToStop.Why));

            // The frontend's listener stops on its own loop, a moment after the
            // frontend was let go of.
            Assert.Multiple(() => {
                Assert.That(() => Refused(modbus), Is.True.After(5000, 50), "the meter still listens for Modbus/TLS");
                Assert.That(Refused(web),          Is.True,                 "the meter still listens on its web port");
            });

        }

        #endregion

        #region LettingGoOfAMeterWhoseStopFails_StopsItsTimers()

        /// <summary>
        /// None of the meter's timers runs on after it was let go of: none of
        /// them would find the meter it was made for.
        /// </summary>
        [Test]
        public async Task LettingGoOfAMeterWhoseStopFails_StopsItsTimers()
        {

            var meter = await Started();

            Assert.That(meter.Clock.Running, Is.Not.Empty, "the meter started no timers of its own");

            Assert.That(async () => await meter.DisposeAsync(), Throws.InstanceOf<InvalidOperationException>());

            Assert.That(meter.Clock.Running, Is.Empty, "timers of a meter that was let go of still run");

        }

        #endregion

        #region LettingGoOfAMeterWhoseStopFails_LetsGoOfItsLogFile()

        /// <summary>
        /// Nothing logged after the meter was let go of reaches its log file,
        /// which the node underneath it has closed.
        /// </summary>
        [Test]
        public async Task LettingGoOfAMeterWhoseStopFails_LetsGoOfItsLogFile()
        {

            var meter = await Started();

            meter.Log.Notice("Written while the meter runs.", "test");

            var file = meter.LogFile;

            Assert.That(file, Is.Not.Null, "the meter wrote no log file");

            Assert.That(async () => await meter.DisposeAsync(), Throws.InstanceOf<InvalidOperationException>());

            meter.Log.Notice("Written after the meter was let go of.", "test");

            var written = Read(file!);

            Assert.Multiple(() => {
                Assert.That(written, Does.Contain    ("Written while the meter runs."));
                Assert.That(written, Does.Not.Contain("Written after the meter was let go of."),
                            "the log file of a meter that was let go of was still written");
            });

        }

        #endregion


        #region (private class) CountedTimers

        /// <summary>
        /// The system's clock, which keeps count of the timers made on it that
        /// were not let go of.
        /// </summary>
        private sealed class CountedTimers : TimeProvider
        {

            private readonly List<Counted> timers = [];

            /// <summary>
            /// When each timer still running was made to fire first, and how
            /// often after that.
            /// </summary>
            public IReadOnlyList<String> Running
            {
                get
                {
                    lock (timers)
                        return timers.Where(timer => !timer.Disposed).Select(timer => timer.ToString()).ToArray();
                }
            }

            public override ITimer CreateTimer(TimerCallback Callback, Object? State, TimeSpan DueTime, TimeSpan Period)
            {

                var timer = new Counted(System.CreateTimer(Callback, State, DueTime, Period), DueTime, Period);

                lock (timers)
                    timers.Add(timer);

                return timer;

            }

            private sealed class Counted(ITimer Timer, TimeSpan DueTime, TimeSpan Period) : ITimer
            {

                public Boolean Disposed { get; private set; }

                public Boolean Change(TimeSpan DueTime, TimeSpan Period)
                    => Timer.Change(DueTime, Period);

                public void Dispose()
                {
                    Disposed = true;
                    Timer.Dispose();
                }

                public ValueTask DisposeAsync()
                {
                    Disposed = true;
                    return Timer.DisposeAsync();
                }

                public override String ToString()
                    => $"due {DueTime}, every {Period}";

            }

        }

        #endregion

        #region (private class) FailingToStop

        /// <summary>
        /// A meter whose own part of stopping fails before it has done any of
        /// it.
        /// </summary>
        private sealed class FailingToStop(String          ServerPfxPath,
                                           String          ClientCACertPath,
                                           Int32           ListenPort,
                                           IPPort          HTTPPort,
                                           String          DataPath,
                                           WWCPConfigFile  ConfigFile,
                                           CountedTimers   Clock)

            : ModbusTLSEnergyMeter(SerialNumber:       "meter-stop-fails-001",
                                   ServerPfxPath:      ServerPfxPath,
                                   ServerPfxPassword:  "demo",
                                   ClientCACertPath:   ClientCACertPath,
                                   ListenAddress:      NetIPAddress.Loopback,
                                   ListenPort:         ListenPort,
                                   HTTPHostname:       IPv4Address.Localhost,
                                   HTTPPort:           HTTPPort,
                                   DataPath:           DataPath,
                                   ConfigFile:         ConfigFile,
                                   LogToConsole:       false,
                                   TimeProvider:       Clock)

        {

            /// <summary>
            /// What its stopping says.
            /// </summary>
            public const String Why = "What this meter holds open would not end.";

            /// <summary>
            /// The clock its timers were made on.
            /// </summary>
            public CountedTimers Clock { get; } = Clock;

            /// <summary>
            /// The file its log is written to, once something was.
            /// </summary>
            public String? LogFile
                => fileLog?.CurrentFile;

            protected override Task OnStopping()
                => Task.FromException(new InvalidOperationException(Why));

        }

        #endregion

    }

}
