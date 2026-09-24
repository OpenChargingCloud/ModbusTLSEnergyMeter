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

using System.Net;
using System.Net.Sockets;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The event stream every browser hangs on, as a proxy in front of the
    /// meter sees it.
    /// </summary>
    /// <remarks>
    /// Against a meter that is started, because what is tested is what goes
    /// over the wire: a header, and what the stream says while nothing
    /// happens. The charging station's two tests (ChargingStation 098e580),
    /// against a meter whose time synchronisation is switched off, so that
    /// nothing leaves the machine and nothing is logged that the test did not
    /// write.
    /// </remarks>
    [TestFixture]
    public class EventStreamTests
    {

        #region Data

        private String                 fixtureDirectory  = "";
        private String                 pkiDirectory      = "";
        private String                 directory         = "";
        private Int32                  httpPort;
        private ModbusTLSEnergyMeter?  meter;

        #endregion

        #region OneTimeSetup / Setup / TearDown / OneTimeTearDown

        [OneTimeSetUp]
        public async Task OneTimeSetup()
        {

            fixtureDirectory  = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "event-stream-" + Guid.NewGuid().ToString("N")[..12]);
            pkiDirectory      = Path.Combine(fixtureDirectory, "pki");

            await new ModbusPKI().BuildPKI(pkiDirectory);

        }

        [SetUp]
        public async Task Setup()
        {

            directory = Path.Combine(fixtureDirectory, Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

            var configuration = Path.Combine(directory, MeterConfigFile.DefaultFileName);

            File.WriteAllText(configuration, """{ "nts": { "enabled": false } }""");

            httpPort = FreeTCPPort();

            meter    = new ModbusTLSEnergyMeter(
                           SerialNumber:       "meter-event-stream-001",
                           ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                           ServerPfxPassword:  "demo",
                           ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                           ListenAddress:      NetIPAddress.Loopback,
                           ListenPort:         FreeTCPPort(),
                           HTTPHostname:       IPv4Address.Localhost,
                           HTTPPort:           IPPort.Parse(httpPort),
                           DataPath:           Path.Combine(directory, "data"),
                           ConfigFile:         new MeterConfigFile(configuration),
                           LogKeepDays:        0,
                           LogToConsole:       false
                       );

            await meter.StartAsync();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (meter is not null)
                await meter.DisposeAsync();

            meter = null;

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A file the meter still holds is not what is under test.
            }

        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {

            try
            {
                if (Directory.Exists(fixtureDirectory))
                    Directory.Delete(fixtureDirectory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region TheStreamAsksAProxyNotToBufferIt()

        /// <summary>
        /// "X-Accel-Buffering: no" on the event stream.
        /// </summary>
        /// <remarks>
        /// nginx buffers what it passes on unless it is told otherwise, and a
        /// buffered event stream reaches the browser as nothing at all - not
        /// even its header - until a buffer is full or nginx gives up on it
        /// after 60 silent seconds. The Logs page says "reconnecting ..." all
        /// the while, and never asks for its snapshot, which it does when the
        /// stream opens.
        /// </remarks>
        [Test]
        public async Task TheStreamAsksAProxyNotToBufferIt()
        {

            using var http      = await SignedIn();
            using var response  = await http.GetAsync("api/v1/events", HttpCompletionOption.ResponseHeadersRead);

            Assert.Multiple(() => {
                Assert.That(response.StatusCode,                                                 Is.EqualTo(HttpStatusCode.OK));
                Assert.That(response.Content.Headers.ContentType?.MediaType,                     Is.EqualTo("text/event-stream"));
                Assert.That(response.Headers.TryGetValues("X-Accel-Buffering", out var values),  Is.True, "the header is there");
                Assert.That(values,                                                              Is.EqualTo(new[] { "no" }));
            });

        }

        #endregion

        #region ASilentStreamSaysSoAndThenCarriesOn()

        /// <summary>
        /// A comment whenever the stream has been silent for the heartbeat, and
        /// the next entry after it as if nothing had happened.
        /// </summary>
        /// <remarks>
        /// nginx gives up on an upstream that has sent nothing for 60 seconds,
        /// and a meter nothing is reading from says nothing for longer than
        /// that. The second half is the one that could go wrong: the stream
        /// waits for the next entry across the heartbeat instead of asking for
        /// it again, and an entry that arrived during one must neither be lost
        /// nor come twice.
        /// </remarks>
        [Test]
        public async Task ASilentStreamSaysSoAndThenCarriesOn()
        {

            meter!.API.EventStreamHeartbeat = TimeSpan.FromMilliseconds(300);

            using var http    = await SignedIn();
            using var stream  = await EventStream.Open(http);

            var heartbeat     = await stream.ReadUntil(": keep-alive");

            // Without it there is nothing to carry on after: a read that gives
            // up takes the stream with it.
            Assert.That(heartbeat, Is.True, "a comment came while nothing was logged");

            var marker        = "A line for the event stream " + Guid.NewGuid().ToString("N")[..8];
            meter.Log.Info(marker, "test");

            var entry         = await stream.ReadUntil(marker);

            // And the one after it, to be sure the stream is still waiting for
            // entries and not only for the heartbeat.
            var second        = marker + " (second)";
            meter.Log.Info(second, "test");

            var secondEntry   = await stream.ReadUntil(second);

            // The first one in quotes, which is how its message is written - so
            // that the second one, which begins with it, is not counted too.
            var delivered     = stream.Received.Split($"\"{marker}\"").Length - 1;

            Assert.Multiple(() => {
                Assert.That(entry,        Is.True,         "the entry logged after the heartbeat arrived");
                Assert.That(secondEntry,  Is.True,         "and so did the one after it");
                Assert.That(delivered,    Is.EqualTo(1),   "once");
            });

        }

        #endregion

        #region AStreamWaitingForItsNextEntryDoesNotHoldTheStop()

        /// <summary>
        /// Stopping the meter ends a stream that is waiting for its next entry,
        /// and does not wait for it.
        /// </summary>
        /// <remarks>
        /// The stream waits for the next entry across heartbeats now, and what
        /// it waits on has to end when the meter stops: the enumerator cannot
        /// be disposed while it is still waiting, and a stream that did not end
        /// would hold the shutdown for as long as a browser kept the Logs page
        /// open. Stopped once the stream is parked - after a heartbeat, which
        /// it only sends while it waits - so that this is the case being
        /// tested, and not a stream still busy replaying what was cached.
        /// </remarks>
        [Test]
        public async Task AStreamWaitingForItsNextEntryDoesNotHoldTheStop()
        {

            meter!.API.EventStreamHeartbeat = TimeSpan.FromMilliseconds(300);

            using var http    = await SignedIn();
            using var stream  = await EventStream.Open(http);

            Assert.That(await stream.ReadUntil(": keep-alive"), Is.True, "the stream is waiting for its next entry");

            var stopping      = meter.StopAsync();
            var stopped       = await Task.WhenAny(stopping, Task.Delay(TimeSpan.FromSeconds(10))) == stopping;

            Assert.Multiple(async () => {
                Assert.That(stopped,                                    Is.True, "the meter stopped within ten seconds");
                Assert.That(await stream.EndsWithin(TimeSpan.FromSeconds(10)), Is.True, "and the stream ended");
            });

        }

        #endregion

        #region ABrowserThatHasGoneIsLetGo()

        /// <summary>
        /// A browser that has gone is noticed by the next heartbeat, and its
        /// stream ends and lets go of its subscription.
        /// </summary>
        /// <remarks>
        /// A browser closing the Logs page says nothing, and a server learns
        /// that a client has gone only by writing to it - which a stream on a
        /// quiet meter does with its heartbeat and nothing else. Without that,
        /// a closed page would stay subscribed until the meter stopped, with
        /// every entry queued for it. What ends the subscription is the
        /// enumerator being stopped once a heartbeat could not be written, so
        /// that is what this looks at: the event source's own count of the
        /// clients it is writing to. Parked first, after a heartbeat, as in
        /// the test before.
        /// </remarks>
        [Test]
        public async Task ABrowserThatHasGoneIsLetGo()
        {

            meter!.API.EventStreamHeartbeat = TimeSpan.FromMilliseconds(300);

            var events  = (HTTPEventSource<JObject>) meter.API.Events;
            var http    = await SignedIn();
            var stream  = await EventStream.Open(http);

            Assert.Multiple(async () => {
                Assert.That(await stream.ReadUntil(": keep-alive"),  Is.True,        "the stream is waiting for its next entry");
                Assert.That(events.NumberOfConnectedClients,         Is.EqualTo(1),  "and the browser is subscribed");
            });

            // The page is closed: the connection goes, and nothing is said.
            stream.Dispose();
            http.  Dispose();

            var giveUpAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10);

            while (events.NumberOfConnectedClients > 0 && DateTimeOffset.UtcNow < giveUpAt)
                await Task.Delay(50);

            Assert.That(events.NumberOfConnectedClients, Is.Zero, "the subscription ended within ten seconds");

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// A client signed in as the administrator made at the first start,
        /// keeping the cookie it was given.
        /// </summary>
        private async Task<HttpClient> SignedIn()
        {

            var http = new HttpClient(new HttpClientHandler { UseCookies = true }) {
                           BaseAddress = new Uri($"http://127.0.0.1:{httpPort}/"),
                           Timeout     = Timeout.InfiniteTimeSpan
                       };

            using var login = await http.PostAsync("accounts/auth/login",
                                                   new StringContent($$"""{ "login": "{{meter!.GeneratedUserId}}", "password": "{{meter.GeneratedPassword}}" }""",
                                                                     Encoding.UTF8, "application/json"));

            Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.OK), "the administrator could not sign in");

            return http;

        }

        private static Int32 FreeTCPPort()
        {

            var listener = new TcpListener(NetIPAddress.Loopback, 0);

            listener.Start();
            var port = ((IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return port;

        }

        /// <summary>
        /// The stream, opened and read until something has come down it.
        /// </summary>
        private sealed class EventStream : IDisposable
        {

            /// <summary>
            /// How long a test waits for something to arrive before it says the
            /// stream is broken.
            /// </summary>
            private static readonly TimeSpan  Timeout = TimeSpan.FromSeconds(20);

            private readonly HttpResponseMessage  response;
            private readonly StreamReader         reader;
            private readonly StringBuilder        read = new ();

            /// <summary>
            /// Everything that has come down the stream so far.
            /// </summary>
            public String Received
                => read.ToString();

            private EventStream(HttpResponseMessage  Response,
                                StreamReader         Reader)
            {
                this.response  = Response;
                this.reader    = Reader;
            }

            /// <summary>
            /// Open the stream and check that it was opened.
            /// </summary>
            public static async Task<EventStream> Open(HttpClient HTTP)
            {

                var response = await HTTP.GetAsync("api/v1/events", HttpCompletionOption.ResponseHeadersRead);

                Assert.Multiple(() => {
                    Assert.That(response.IsSuccessStatusCode,                     Is.True,
                                "The event stream did not open, so the test using it would pass for the wrong reason.");
                    Assert.That(response.Content.Headers.ContentType?.MediaType,  Is.EqualTo("text/event-stream"));
                });

                return new EventStream(response, new StreamReader(await response.Content.ReadAsStreamAsync()));

            }

            /// <summary>
            /// Read until the given text has come through, or until waiting
            /// stops being reasonable.
            /// </summary>
            public async Task<Boolean> ReadUntil(String Text)
            {

                var buffer = new Char[1024];

                using var cancellation = new CancellationTokenSource(Timeout);

                try
                {

                    while (!read.ToString().Contains(Text, StringComparison.Ordinal))
                    {

                        var count = await reader.ReadAsync(buffer, cancellation.Token);

                        if (count == 0)
                            return false;

                        read.Append(buffer, 0, count);

                    }

                    return true;

                }
                catch (OperationCanceledException)
                {
                    return false;
                }

            }

            /// <summary>
            /// Read until the other side ends the stream, or until the given
            /// time is up.
            /// </summary>
            public async Task<Boolean> EndsWithin(TimeSpan Time)
            {

                var buffer = new Char[1024];

                using var cancellation = new CancellationTokenSource(Time);

                try
                {

                    while (true)
                    {

                        var count = await reader.ReadAsync(buffer, cancellation.Token);

                        if (count == 0)
                            return true;

                        read.Append(buffer, 0, count);

                    }

                }
                catch (OperationCanceledException)
                {
                    return false;
                }
                catch (IOException)
                {
                    // A connection the server closed rather than finished is
                    // an end as well.
                    return true;
                }

            }

            public void Dispose()
            {
                reader.  Dispose();
                response.Dispose();
            }

        }

        #endregion

    }

}
