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

using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// The stores the meter kept its certificates in before they were the
    /// node's: "modbus" and "web" with a directory per certificate, and
    /// "trust" with a file per accepted CA - moved into the node's certificate
    /// store once, at a start.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A certificate with its key becomes a TLS identity for the listener its
    /// store was for, keeping its note as its label. A key with a signing
    /// request becomes a request, answered by that identity where there is
    /// one, so that it can be certified again. An accepted CA becomes a client
    /// root, switched off where it was.
    /// </para>
    /// <para>
    /// What was moved is not deleted but put below "moved", so that nothing is
    /// lost if a start went wrong. What could not be moved - a key of a kind
    /// this platform cannot hold with its certificate - stays where it is and
    /// is named in the log, at every start, until somebody takes it away.
    /// </para>
    /// </remarks>
    public static class OldCertificateStores
    {

        #region Data

        /// <summary>
        /// The directory below the certificate store what was moved is kept in.
        /// </summary>
        public const String MovedDirectoryName = "moved";

        /// <summary>
        /// The directory the accepted client CAs were kept in.
        /// </summary>
        public const String TrustDirectoryName = "trust";

        #endregion


        #region MoveInto(Store, Requests, Log, Now)

        /// <summary>
        /// Move whatever the old stores beside the node's store still hold into
        /// it, and say what was moved and what could not be.
        /// </summary>
        /// <param name="Store">The node's certificate store; the old stores are in its directory.</param>
        /// <param name="Requests">Where the signing requests go.</param>
        /// <param name="Log">Where to say what was moved.</param>
        /// <param name="Now">What time it is.</param>
        public static void MoveInto(CertificateStore  Store,
                                    SigningRequests   Requests,
                                    EventLog          Log,
                                    DateTimeOffset    Now)
        {

            foreach (var listener in ListenerCertificates.All)
                MoveIdentities(Store, Requests, Log, Now, listener);

            MoveClientCAs(Store, Log);

        }

        #endregion


        #region (private static) MoveIdentities(Store, Requests, Log, Now, Listener)

        private static void MoveIdentities(CertificateStore  Store,
                                           SigningRequests   Requests,
                                           EventLog          Log,
                                           DateTimeOffset    Now,
                                           String            Listener)
        {

            var old = Path.Combine(Store.Directory, Listener);

            if (!Directory.Exists(old))
                return;

            foreach (var directory in Directory.EnumerateDirectories(old).Order(StringComparer.Ordinal).ToArray())
            {

                var id = Path.GetFileName(directory);

                try
                {

                    var metaFile = Path.Combine(directory, "meta.json");

                    if (!File.Exists(metaFile))
                        continue;

                    var meta         = SigningRequest.ReadJSON(File.ReadAllText(metaFile));
                    var note         = meta["note"]?.Value<String>();
                    var keyFile      = Path.Combine(directory, "key.pem");
                    var requestFile  = Path.Combine(directory, "request.pem");
                    var pfxFile      = Path.Combine(directory, "certificate.pfx");
                    var pemFile      = Path.Combine(directory, "certificate.pem");

                    CertificateEntry? entry = null;

                    #region The certificate and its key, if there is one

                    Byte[]? credential = null;
                    String? error      = null;

                    if (File.Exists(pfxFile))
                        credential = PKCS12Of(File.ReadAllBytes(pfxFile));

                    else if (File.Exists(pemFile) && File.Exists(keyFile) &&
                             !SigningRequests.TryCredential(File.ReadAllText(pemFile),
                                                            File.ReadAllText(keyFile),
                                                            Now,
                                                            out credential,
                                                            out error,
                                                            RefuseExpired: false))
                    {
                        Log.Warning($"The {Listener} certificate '{note ?? id}' could not be moved into the certificate store, " +
                                    $"and stays in '{directory}': {error}",
                                    "certificates", Listener);
                        continue;
                    }

                    if (credential is not null &&
                        !Store.Import(credential, CertificateKind.TLSServerIdentity, null, note, [ Listener ], out entry, out error))
                    {
                        Log.Warning($"The {Listener} certificate '{note ?? id}' could not be moved into the certificate store, " +
                                    $"and stays in '{directory}': {error}",
                                    "certificates", Listener);
                        continue;
                    }

                    #endregion

                    #region The key and its signing request, if they were made here

                    if (File.Exists(keyFile) && File.Exists(requestFile))
                        Requests.Adopt(
                            new SigningRequest(
                                id,
                                Listener,
                                SigningRequest.TryParseTimestamp(meta["createdAt"], out var createdAt) ? createdAt : Now,
                                meta["subject"]?.Value<String>() ?? entry?.Subject ?? "",
                                [.. meta["dnsNames"]?.   Values<String>().OfType<String>() ?? []],
                                [.. meta["ipAddresses"]?.Values<String>().OfType<String>() ?? []],
                                SigningRequests.AlgorithmOf(meta["keyType"]?.Value<String>())?.Id ?? meta["keyType"]?.Value<String>() ?? "unknown",
                                note,
                                entry is not null ? [ entry.Id ] : []
                            ),
                            File.ReadAllText(keyFile),
                            File.ReadAllText(requestFile)
                        );

                    else if (entry is null)
                        // Neither a certificate nor a request: nothing to move,
                        // and nothing to lose by leaving it.
                        continue;

                    #endregion

                    Keep(directory, Path.Combine(Store.Directory, MovedDirectoryName, Listener, id));

                    Log.Notice(
                        entry is not null
                            ? $"The {Listener} certificate '{entry.Label}' is in the certificate store now, as {entry.Id} for the {Listener} listener."
                            : $"The {Listener} signing request '{note ?? id}' is kept with the other requests now, still waiting for its certificate.",
                        "certificates", Listener
                    );

                }
                catch (Exception e)
                {
                    Log.Warning($"The {Listener} certificate in '{directory}' could not be moved into the certificate store: {e.Message}",
                                "certificates", Listener);
                }

            }

            RemoveWhenEmpty(old);

        }

        #endregion

        #region (private static) MoveClientCAs(Store, Log)

        private static void MoveClientCAs(CertificateStore  Store,
                                          EventLog          Log)
        {

            var old = Path.Combine(Store.Directory, TrustDirectoryName);

            if (!Directory.Exists(old))
                return;

            foreach (var jsonFile in Directory.EnumerateFiles(old, "*.json").Order(StringComparer.Ordinal).ToArray())
            {

                var pemFile = Path.ChangeExtension(jsonFile, ".pem");

                try
                {

                    if (!File.Exists(pemFile))
                        continue;

                    var meta       = SigningRequest.ReadJSON(File.ReadAllText(jsonFile));
                    var name       = meta["name"]?.Value<String>() ?? Path.GetFileNameWithoutExtension(jsonFile);
                    var enabled    = meta["enabled"]?.Value<Boolean>() ?? true;
                    var chain      = new X509Certificate2Collection();

                    chain.ImportFromPem(File.ReadAllText(pemFile));

                    var moved      = new List<CertificateEntry>();
                    var failed     = false;

                    foreach (var certificate in chain)
                    {

                        var label = chain.Count == 1
                                        ? name
                                        : $"{name} - {CertificateEntry.CommonNameOf(certificate)}";

                        if (!Store.Import(Encoding.ASCII.GetBytes(certificate.ExportCertificatePem()),
                                          CertificateKind.ClientRoot,
                                          null,
                                          label,
                                          out var entry,
                                          out var error))
                        {
                            Log.Warning($"The accepted CA '{label}' could not be moved into the certificate store, and stays in '{pemFile}': {error}",
                                        "certificates", "trust");
                            failed = true;
                            break;
                        }

                        // Switched off where it was: a CA somebody stopped
                        // accepting is not accepted again by being moved.
                        if (!enabled && Store.SetActive(entry.Id, false, out var switchedOff, out _))
                            entry = switchedOff;

                        moved.Add(entry);

                    }

                    if (failed)
                        continue;

                    var target = Path.Combine(Store.Directory, MovedDirectoryName, TrustDirectoryName);

                    Keep(jsonFile, Path.Combine(target, Path.GetFileName(jsonFile)));
                    Keep(pemFile,  Path.Combine(target, Path.GetFileName(pemFile)));

                    Log.Notice($"The accepted CA '{name}' is in the certificate store now, as the client root{(moved.Count == 1 ? "" : "s")} " +
                               $"{String.Join(", ", moved.Select(entry => entry.Id))}{(enabled ? "" : ", switched off as it was")}.",
                               "certificates", "trust");

                }
                catch (Exception e)
                {
                    Log.Warning($"The accepted CA in '{pemFile}' could not be moved into the certificate store: {e.Message}",
                                "certificates", "trust");
                }

            }

            RemoveWhenEmpty(old);

        }

        #endregion


        #region (private static) PKCS12Of(Content)

        /// <summary>
        /// The PKCS#12 in a file of the old store - which wrote the one it was
        /// started with as base64 text rather than as the binary file.
        /// </summary>
        private static Byte[] PKCS12Of(Byte[] Content)
        {

            // A PKCS#12 is a DER sequence and begins with 0x30; the base64 of one
            // begins with 'M'.
            if (Content.Length > 0 && Content[0] != 0x30)
            {
                try
                {
                    return Convert.FromBase64String(Encoding.ASCII.GetString(Content).Trim());
                }
                catch (FormatException)
                { }
            }

            return Content;

        }

        #endregion

        #region (private static) Keep(From, To) / RemoveWhenEmpty(Directory)

        /// <summary>
        /// Put what was moved below "moved", under another name when something of
        /// that name is there already.
        /// </summary>
        private static void Keep(String  From,
                                 String  To)
        {

            Directory.CreateDirectory(Path.GetDirectoryName(To)!);

            var target = To;

            for (var n = 2; Directory.Exists(target) || File.Exists(target); n++)
                target = $"{To}.{n}";

            if (Directory.Exists(From))
                Directory.Move(From, target);
            else
                File.Move(From, target);

        }

        private static void RemoveWhenEmpty(String Directory)
        {
            try
            {
                if (System.IO.Directory.Exists(Directory) && !System.IO.Directory.EnumerateFileSystemEntries(Directory).Any())
                    System.IO.Directory.Delete(Directory);
            }
            catch (Exception)
            { }
        }

        #endregion

    }

}
