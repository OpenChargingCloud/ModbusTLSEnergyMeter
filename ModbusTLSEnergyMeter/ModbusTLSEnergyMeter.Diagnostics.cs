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

using System.Diagnostics;
using System.Globalization;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.NTS;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// Making this meter ask one of its time servers everything, to find out
    /// where the asking gets to.
    /// </summary>
    /// <remarks>
    /// The test writes to the event log as it goes, and not only at the end.
    /// That is the point of it: somebody whose time server does not answer
    /// wants to know which step failed - the name, the TLS handshake, the key
    /// exchange, the NTP packet - and a single line saying "it did not work"
    /// tells them to go and find out somewhere else.
    ///
    /// Because it is in the log, it is also in the live stream every open
    /// browser is hanging on. So the Logs page of somebody watching shows what
    /// somebody else pressed, which is the right way round for a meter that
    /// several people look after.
    ///
    /// The vehicle's and the charging station's test, ported: the three are
    /// siblings, and a server that answers one of them differently from
    /// another would be a difference nobody could explain.
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region (static) TLSSteps(TLS, Now)

        /// <summary>
        /// What a time server's TLS session and certificate say, and whether that
        /// held up - as steps of a server's test, from the session to the verdict.
        /// </summary>
        /// <remarks>
        /// Every certificate of the chain with both ends of its validity and the
        /// days that are left: the root's as much as the server's. A root can be
        /// pinned, and a pinned root that runs out stops whatever relies on it,
        /// however new the server's certificate is. The root also comes with its
        /// SHA-256 fingerprint, which is what a pin is compared with.
        ///
        /// The chain is the one this meter built, not the one the server sent -
        /// see NTSKE_TLSInfo.ValidatedChain. Where none was built, the server's
        /// certificates are shown as they came.
        ///
        /// The verdict is Norn's, taken from what its validation decided; the
        /// reasons are its chain's, in words, because the platform's own texts
        /// for them are in whatever language the machine speaks.
        /// </remarks>
        /// <param name="TLS">What the key exchange kept of its TLS session.</param>
        /// <param name="Now">The moment the days that are left are counted from.</param>
        public static IEnumerable<(String Level, String Text)> TLSSteps(NTSKE_TLSInfo   TLS,
                                                                         DateTimeOffset  Now)
        {

            var session = new[] {
                              TLS.NegotiatedTLSVersion,
                              TLS.NegotiatedCipherSuite,
                              TLS.NegotiatedApplicationProtocol is String protocol ? $"ALPN {protocol}" : null
                          }.Where(part => part is not null).ToArray();

            if (session.Length > 0)
                yield return ("info", $"{String.Join(", ", session)}.");

            if (TLS.ServerCertificate is null)
                yield break;

            IReadOnlyList<X509Certificate2> chain = TLS.ValidatedChain.  Count > 0 ? TLS.ValidatedChain
                                                  : TLS.CertificateChain.Count > 0 ? TLS.CertificateChain
                                                  : [ TLS.ServerCertificate ];

            for (var position = 0; position < chain.Count; position++)
            {

                var certificate = chain[position];
                var selfSigned  = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData);
                var last        = position == chain.Count - 1;

                var what        = position == 0  ? selfSigned ? "Server certificate, self-signed" : "Server certificate"
                                : !last          ? "Intermediate CA"
                                : selfSigned     ? "Root CA"
                                :                  "Last in the chain, and no root";

                var (level, validity) = Validity(certificate, Now);

                yield return (level,
                              String.Concat(
                                  $"{what}: {certificate.Subject}",
                                  position == 0 && NamesOf(certificate) is String names ? $", for {names}"               : "",
                                  last && !selfSigned                                   ? $", issued by {certificate.Issuer}" : "",
                                  $"; {KeyAlgorithmOf(certificate)}, {certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value}",
                                  $"; {validity}."
                              ));

                // What a pin is compared with - for the certificate the chain
                // ends at, which is the server's own when it signed itself.
                if (last && selfSigned)
                    yield return ("info", $"{(position == 0 ? "Its" : "The root's")} SHA-256 fingerprint: {ThumbprintOf(certificate)}.");

            }

            var host   = TLS.CheckedHostname?.Trimmed;
            var errors = TLS.CertificatePolicyErrors ?? SslPolicyErrors.None;

            if (errors == SslPolicyErrors.None)
                yield return ("notice", String.Concat(
                                            "Validated: the chain ends at a root this machine trusts",
                                            TLS.RevocationMode == X509RevocationMode.Online ? ", nothing in it is revoked (asked online)"                : "",
                                            host is not null                                ? $", and '{host}' is one of the server certificate's names" : "",
                                            "."
                                        ));

            else
            {

                var reasons = TLS.ChainStatus.Select(ReasonFor).Distinct().ToList();

                if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && reasons.Count == 0)
                    reasons.Add("its chain did not validate");

                if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                    reasons.Add(host is not null
                                    ? $"'{host}' is not one of the server certificate's names"
                                    : "it was issued for another name");

                if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                    reasons.Add("no certificate came");

                yield return ("error", $"Not validated: {String.Join("; ", reasons)}.");

            }

        }

        /// <summary>
        /// Both ends of a certificate's validity, and where the given moment is
        /// between them - with the level that deserves.
        /// </summary>
        /// <remarks>
        /// A week's warning, as Norn's monitoring gives by default. Inside its
        /// validity is information; outside it, on either side, is an error.
        /// </remarks>
        private static (String Level, String Text) Validity(X509Certificate2  Certificate,
                                                            DateTimeOffset    Now)
        {

            var notBefore  = new DateTimeOffset(Certificate.NotBefore.ToUniversalTime());
            var notAfter   = new DateTimeOffset(Certificate.NotAfter. ToUniversalTime());
            var span       = String.Create(CultureInfo.InvariantCulture, $"valid {notBefore:yyyy-MM-dd HH:mm:ss} to {notAfter:yyyy-MM-dd HH:mm:ss} UTC");

            if (Now < notBefore)
                return ("error",   $"{span}, not valid for another {Days(notBefore - Now)} day(s)");

            if (Now > notAfter)
                return ("error",   $"{span}, expired {Days(Now - notAfter)} day(s) ago");

            var left = Days(notAfter - Now);

            return (left <= 7 ? "warning" : "info",
                    $"{span}, {left} day(s) left");

            static Int32 Days(TimeSpan Span)
                => (Int32) Math.Floor(Span.TotalDays);

        }

        /// <summary>
        /// The names a certificate is for - its subject alternative names, which
        /// are the only ones a host name is matched against - or null when it
        /// names none.
        /// </summary>
        private static String? NamesOf(X509Certificate2 Certificate)
        {

            var alternative = Certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();

            if (alternative is null)
                return null;

            var names = alternative.EnumerateDnsNames().
                            Concat(alternative.EnumerateIPAddresses().Select(address => address.ToString())).
                            ToArray();

            return names.Length == 0 ? null
                 : names.Length <= 4 ? String.Join(", ", names)
                 :                     $"{String.Join(", ", names.Take(4))} and {names.Length - 4} more";

        }

        /// <summary>
        /// Why a chain did not validate, in words.
        /// </summary>
        private static String ReasonFor(X509ChainStatusFlags Status)

            => Status switch {
                   X509ChainStatusFlags.UntrustedRoot            => "its root is not one this machine trusts",
                   X509ChainStatusFlags.PartialChain             => "no chain up to a root could be built",
                   X509ChainStatusFlags.NotTimeValid             => "a certificate in it is outside its validity",
                   X509ChainStatusFlags.Revoked                  => "a certificate in it has been revoked",
                   X509ChainStatusFlags.RevocationStatusUnknown  => "whether a certificate in it is revoked could not be found out",
                   X509ChainStatusFlags.OfflineRevocation        => "the revocation lists could not be reached",
                   X509ChainStatusFlags.NotSignatureValid        => "a signature in it does not verify",
                   X509ChainStatusFlags.NotValidForUsage         => "a certificate in it is not meant for this use",
                   X509ChainStatusFlags.Cyclic                   => "the chain runs in a circle",
                   _                                             => Status.ToString()
               };

        /// <summary>
        /// What kind of key a certificate carries, written the way somebody
        /// comparing it against a specification would write it: the curve
        /// named, and not only its size.
        /// </summary>
        /// <remarks>
        /// Beside the steps rather than taken from the certificate store, as
        /// the vehicle does: the store of this meter writes key types the way
        /// it asks for keys - "ecdsa-p256" - which is a name for a request and
        /// not a description of a certificate somebody else issued.
        /// </remarks>
        private static String KeyAlgorithmOf(X509Certificate2 Certificate)
        {

            using var ecdsa = Certificate.GetECDsaPublicKey();

            if (ecdsa is not null)
            {

                var curve = ecdsa.KeySize switch {
                                256  => "P-256",
                                384  => "P-384",
                                521  => "P-521",
                                _    => $"{ecdsa.KeySize}-bit"
                            };

                return $"ECDSA {curve}";

            }

            using var rsa = Certificate.GetRSAPublicKey();

            return rsa is not null
                       ? $"RSA {rsa.KeySize}-bit"
                       : Certificate.PublicKey.Oid.FriendlyName ?? Certificate.PublicKey.Oid.Value ?? "unknown";

        }

        /// <summary>
        /// A certificate's SHA-256 fingerprint, in lower-case hexadecimal -
        /// SHA-256 rather than X509Certificate2.Thumbprint, which is SHA-1 and
        /// has no business identifying anything in 2026.
        /// </summary>
        private static String ThumbprintOf(X509Certificate2 Certificate)

            => Convert.ToHexString(SHA256.HashData(Certificate.RawData)).ToLowerInvariant();

        #endregion

        #region TestTimeServerAsync(Host = null, CancellationToken = default)

        /// <summary>
        /// Ask one time server everything there is to ask, and write down each
        /// answer as it comes.
        /// </summary>
        /// <remarks>
        /// "Check the clock now" says whether the group has a time. This says
        /// where one server got to: the name resolved to these addresses, the
        /// TCP connection took this long, the TLS handshake that long, the
        /// certificate claimed this and held up or did not, the key exchange
        /// agreed on this algorithm and handed over that many cookies and named
        /// these NTP servers, and the authenticated NTP request went to this
        /// endpoint and came back that far off. A server that fails does so at
        /// one of those, and which one is the whole of what somebody needs.
        ///
        /// <b>Two kinds of "which server".</b> A name that is not the single
        /// client's is treated as a time server in its own right: its own key
        /// exchange, its own time request. An address is treated as one of the
        /// servers the single client's exchange named - the key exchange happens
        /// where it must, with the host that has a certificate, and the
        /// authenticated request is then directed at that address with the
        /// cookies that exchange issued. Which is what RFC 8915 section 4.1.7
        /// describes: the negotiated server is the one "that will accept the
        /// supplied cookies".
        ///
        /// An address cannot have a key exchange of its own - the TLS
        /// certificate has to be checked against a name - and a key exchange
        /// very commonly names addresses, so this is the ordinary case rather
        /// than the awkward one.
        ///
        /// The clock of this meter is not stepped by any of it, the same as
        /// "Check the clock now".
        /// </remarks>
        /// <param name="Host">
        /// Which time server: a name to ask in its own right, an address to ask
        /// among the ones the single client's exchange named, or nothing for
        /// the single client's server itself.
        /// </param>
        public async Task<JObject> TestTimeServerAsync(String?            Host                = null,
                                                       CancellationToken  CancellationToken   = default)
        {

            var clock  = Stopwatch.StartNew();
            var steps  = new JArray();

            void Step(String Level, String Text)
                => steps.Add(new JObject(
                       new JProperty("at_ms",  clock.ElapsedMilliseconds),
                       new JProperty("level",  Level),
                       new JProperty("text",   Text)
                   ));

            JObject Done(String Where, Boolean OK)
            {
                clock.Stop();
                return new JObject(
                           new JProperty("host",        Where),
                           new JProperty("ok",          OK),
                           new JProperty("runtime_ms",  clock.ElapsedMilliseconds),
                           new JProperty("steps",       steps)
                       );
            }

            #region Which server, and with which settings

            if (!NTSEnabled)
            {
                Step("error", "Time synchronisation is switched off on this meter, so nothing was asked.");
                return Done(Host ?? "", false);
            }

            var configured  = ntsClient;
            var wanted      = Host?.Trim();
            var host        = configured.Hostname;

            /// Set when the time request is to go somewhere other than the host
            /// the key exchange happens with.
            String? directedAt = null;

            if (!String.IsNullOrEmpty(wanted) &&
                !String.Equals(wanted.TrimEnd('.'), host.ToString().TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
            {

                if (System.Net.IPAddress.TryParse(wanted.Trim('[', ']'), out _))
                    // An address cannot have a key exchange of its own: the TLS
                    // certificate is issued for a name. So the exchange stays
                    // with the single client's host, and the time request is
                    // directed at this address with the cookies that exchange
                    // issued - which is what a negotiated server is for.
                    directedAt = wanted.Trim('[', ']');

                else if (!DomainName.TryParse(wanted.TrimEnd('.'), out var other, out _))
                {
                    Step("error", $"'{wanted}' is neither a name nor an address that can be asked.");
                    return Done(wanted, false);
                }

                else
                    host = other;

            }

            var where = directedAt ?? $"{host}";

            // The name as people read it, for every sentence below - the steps
            // and the log alike. Without the root's dot: "ptbtime1.ptb.de." is
            // the name exactly, and in the middle of a line it reads like a
            // typing mistake, which is why everything else this meter prints
            // leaves it out.
            var name  = host.Trimmed;

            // A server of the group is asked on its own ports, which need not
            // be those of the single client: the page tests each server from
            // its own row, and a server with a port of its own would otherwise
            // be asked on the usual one and reported as not answering.
            var entry      = directedAt is null
                                 ? timeSources.Sources.FirstOrDefault(source => source.Hostname.Equals(host))
                                 : null;

            var ntsKEPort  = entry?.NTSKEPort ?? configured.NTSKE_Port;
            var ntpPort    = entry?.NTPPort   ?? configured.NTP_Port;

            Step("info", directedAt is null
                             ? String.Format(CultureInfo.InvariantCulture,
                                             "Asking {0}: key exchange on port {1}, time on port {2}, {3:0.#} second(s) allowed.",
                                             name, ntsKEPort, ntpPort, configured.Timeout?.TotalSeconds ?? 0)
                             : $"Asking {directedAt} for the time, with cookies from a key exchange with {name} - " +
                                "an address cannot have a key exchange of its own, because the TLS certificate is " +
                                "issued for a name.");

            Log.Info($"NTS test: asking {name} ...", "nts", "test");

            #endregion

            #region Does the name resolve

            if (!System.Net.IPAddress.TryParse(host.ToString().TrimEnd('.'), out _))
            {
                try
                {

                    var lookedUp  = await dnsClient.Query(
                                              DNSServiceName.Parse(host.ToString()),
                                              [ DNSResourceRecordTypes.A, DNSResourceRecordTypes.AAAA ],
                                              CancellationToken: CancellationToken
                                          );

                    // The address and not the whole record. A resource
                    // record writes itself out with its class, its time to
                    // live and the moment it expires, which in a line that is
                    // about "does this name resolve" is four facts nobody
                    // asked for and one they did.
                    var addresses = lookedUp.Answers.Take(8).
                                        Select(record => (record.RText ?? record.ToString()).Split(',')[0].Trim()).
                                        ToArray();

                    Step(addresses.Length > 0 ? "info" : "warning",
                         addresses.Length > 0
                             ? $"'{name}' resolves to {String.Join(", ", addresses)}."
                             : $"'{name}' resolved to nothing ({lookedUp.ResponseCode}).");

                }
                catch (Exception e)
                {
                    Step("warning", $"'{name}' could not be looked up here: {e.Message}. Asking anyway.");
                }
            }

            #endregion

            // A client of its own, and not the group's: the exchanges the NTS
            // page lists for each server are the group's, from 'Check the clock
            // now' and the clock check, because those are what the clock is
            // checked with - and a test pressed in between is a question about
            // one server, not a change to what the page says the group last did.
            var asking = new NTSClient(
                             host,
                             NTSKE_Port:    ntsKEPort,
                             NTP_Port:      ntpPort,
                             Timeout:       configured.Timeout,
                             DNSClient:     dnsClient,
                             TimeProvider:  TimeProvider
                         );

            try
            {

                #region The key exchange

                Step("info", "Key exchange over TLS ...");

                var keyExchange = await asking.GetNTSKERecords(CancellationToken: CancellationToken);

                if (keyExchange.Response?.TimingInfo is NTSKE_TimingInfo timing)
                {

                    if (timing.ConnectedIPAddress is not null)
                        Step("info", $"Connected to {timing.ConnectedIPAddress}" +
                                     (timing.ResolvedIPAddresses.Any()
                                          ? $", of {timing.ResolvedIPAddresses.Count()} address(es) that were offered"
                                          : "") + ".");

                    Step("info", "Where the time went: " +
                                 String.Join(", ", new[] {
                                     timing.DNSLookupDuration      is TimeSpan dns  ? $"name {dns.TotalMilliseconds:0} ms"      : null,
                                     timing.TCPConnectDuration     is TimeSpan tcp  ? $"TCP {tcp.TotalMilliseconds:0} ms"       : null,
                                     timing.TLSHandshakeDuration   is TimeSpan tls  ? $"TLS {tls.TotalMilliseconds:0} ms"       : null,
                                     timing.NTSKEProtocolDuration  is TimeSpan ke   ? $"key exchange {ke.TotalMilliseconds:0} ms" : null
                                 }.Where(one => one is not null)) + ".");

                }

                // Before the verdict on the exchange, and whichever way it went:
                // a certificate that was refused is the one to see most of all.
                if (keyExchange.TLSInfo is NTSKE_TLSInfo tlsInfo)
                    foreach (var (level, text) in TLSSteps(tlsInfo, TimeProvider.GetUtcNow()))
                        Step(level, text);

                if (!keyExchange.Success || keyExchange.Response is null)
                {
                    Step("error", $"The key exchange failed ({keyExchange.ErrorCategory}): {keyExchange.ErrorMessage}");
                    Log.Warning($"NTS test: the key exchange with {name} failed: {keyExchange.ErrorMessage}", "nts", "ntske", "test");
                    return Done(where, false);
                }

                var response = keyExchange.Response;

                foreach (var warning in response.WarningMessages)
                    Step("warning", $"The key exchange warned: {warning}");

                Step("notice", $"The key exchange succeeded: {response.AEADAlgorithm}, {response.Cookies.Count()} cookie(s).");

                Step("info", response.NTPv4ServerNames.Any()
                                 ? $"It named these NTP servers: {String.Join(", ", response.NTPv4ServerNames)}."
                                 : "It named no NTP server of its own, so the time is asked of this host.");

                if (directedAt is not null &&
                    !response.NTPv4ServerNames.Any(named => String.Equals(named.Trim('[', ']').TrimEnd('.'),
                                                                          directedAt,
                                                                          StringComparison.OrdinalIgnoreCase)))
                {
                    Step("error", $"This exchange did not name {directedAt}, so the cookies it issued were not said to be " +
                                   "accepted there. Nothing was sent: a cookie spent on a server holding different master " +
                                   "keys is wasted, and the refusal it earns is reported against the wrong machine.");
                    return Done(where, false);
                }

                #endregion

                #region The authenticated time request

                Step("info", "Authenticated NTP request ...");

                var query = await asking.QueryTime(NTSKEResponse:      response,
                                                   NTPServer:          directedAt,
                                                   CancellationToken:  CancellationToken);

                if (!query.Success || query.Response is null)
                {
                    Step("error", $"The NTP request to {query.RemoteDescription} failed " +
                                  $"({query.ErrorCategory}): {query.ErrorMessage}");
                    Log.Warning($"NTS test: the NTP request to {name} failed: {query.ErrorMessage}", "nts", "ntp", "test");
                    return Done(where, false);
                }

                Step("info", $"Answered by {query.RemoteDescription}" +
                             (query.Attempts > 1 ? $", after {query.Attempts} attempts" : "") +
                             $"; {query.RemainingCookiesAfterQuery} cookie(s) left" +
                             (query.NewCookieReceived ? ", and a fresh one came back" : "") + ".");

                if (query.StopwatchRoundTripTime is TimeSpan roundTrip)
                    Step("info", String.Format(CultureInfo.InvariantCulture,
                                               "Round trip {0:0.0} ms.", roundTrip.TotalMilliseconds));

                var offset = query.Response.ClockOffset;

                // Invariant, so that a decimal point stays a point: these
                // sentences are English, and a meter in a German locale would
                // otherwise write "+148,0 ms" in the middle of one.
                Step("notice", offset.HasValue
                                   ? String.Format(CultureInfo.InvariantCulture,
                                                   "This meter's clock is {0:+0.0;-0.0;0} ms off what {1} says.",
                                                   offset.Value.TotalMilliseconds, name)
                                   : $"{name} answered, but said nothing this meter could take an offset from.");

                #endregion

                Step("info", "The clock was not stepped: that is a different thing, with every signed reading hanging " +
                             "off it, and not something a test does by surprise.");

                Log.Notice($"NTS test: {name} answered in {clock.ElapsedMilliseconds} ms.", "nts", "test");

                return Done(where, true);

            }
            catch (Exception e)
            {
                Step("error", $"{e.GetType().Name}: {e.Message}");
                Log.Warning($"NTS test: asking {name} failed: {e.Message}", "nts", "test");
                return Done(where, false);
            }

        }

        #endregion

    }

}
