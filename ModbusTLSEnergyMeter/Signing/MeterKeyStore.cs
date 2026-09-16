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

using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using cloud.charging.open.chargy.Crypto;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// The keys this meter signs readings with, and which of them it uses when
    /// nobody says.
    /// </summary>
    /// <remarks>
    /// One is made at the first start and never goes away: a meter that could
    /// be left without a signing key is a meter that can be silently turned
    /// into one whose readings nobody can check.
    ///
    /// The algorithms are ChargyCore's, so that whatever this meter signs is
    /// signed by the same code that verifies it - plus secp192r1, which is not
    /// in that registry because nobody should choose it today, and which the
    /// Alfen format requires and accepts nothing else for.
    /// </remarks>
    public class MeterKeyStore
    {

        #region Data

        /// <summary>
        /// What the meter makes for itself at the first start.
        /// </summary>
        /// <remarks>
        /// ECDSA over secp256r1 with SHA-256, because that is OCMF's own
        /// algorithm and OCMF is what this meter answers with unless asked for
        /// something else. A first key nobody chose should be the one that
        /// works without being thought about.
        /// </remarks>
        public const String DefaultAlgorithm = "ECDSA-P256";

        /// <summary>
        /// secp192r1, which the Alfen format requires: 25 byte compressed
        /// public keys and 48 byte signatures, and no other curve will parse.
        /// </summary>
        /// <remarks>
        /// Kept out of ChargyCore's registry on purpose - 192 bits is not a
        /// size anybody should pick for something new - and kept here because
        /// a meter that cannot make one cannot produce an Alfen record at all.
        /// </remarks>
        public const String AlfenAlgorithm = "ECDSA-secp192r1";

        private static readonly ECDSASignatureSuite alfenSuite =
            new (AlfenAlgorithm, "secp192r1", "SHA-256");

        private readonly Dictionary<String, MeterKey>  keys      = [];
        private readonly Lock                          cacheLock = new();

        #endregion

        #region Properties

        /// <summary>The directory this store keeps its keys in.</summary>
        public String        Path          { get; }

        /// <summary>Where it reads the time.</summary>
        public TimeProvider  TimeProvider  { get; }

        /// <summary>
        /// What went wrong while reading the store, if anything did.
        /// </summary>
        public String?       LastError     { get; private set; }

        /// <summary>Every key, newest first.</summary>
        public IEnumerable<MeterKey> Keys
        {
            get
            {
                lock (cacheLock)
                    return [.. keys.Values.OrderByDescending(key => key.Id)];
            }
        }

        /// <summary>
        /// The key this meter signs with when a request does not name one.
        /// </summary>
        public MeterKey? Default
        {
            get
            {
                lock (cacheLock)
                    return keys.Values.FirstOrDefault(key => key.IsDefault) ??
                           keys.Values.OrderBy(key => key.Id).FirstOrDefault();
            }
        }

        /// <summary>
        /// The names of every algorithm a key can be made for, weakest last.
        /// </summary>
        public static IEnumerable<String> Algorithms

            => [.. SignatureSuites.Algorithms, AlfenAlgorithm];

        #endregion

        #region Events

        /// <summary>
        /// Raised when a key is made, removed, or becomes the identity.
        /// </summary>
        public event Action<MeterKey?, String>? OnChanged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Open, or create, the signing key store of a meter.
        /// </summary>
        /// <param name="Path">The directory it lives in.</param>
        /// <param name="TimeProvider">Where it reads the time.</param>
        public MeterKeyStore(String         Path,
                             TimeProvider?  TimeProvider   = null)
        {

            this.Path          = System.IO.Path.GetFullPath(Path);
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;

            try
            {
                Directory.CreateDirectory(this.Path);
                Reload();
            }
            catch (Exception e)
            {
                LastError = $"The signing key store at '{this.Path}' could not be read: {e.Message}";
            }

        }

        #endregion


        #region SuiteFor(Algorithm)

        /// <summary>
        /// The signature suite of the given algorithm, or null when this meter
        /// does not know it.
        /// </summary>
        public static ISignatureSuite? SuiteFor(String? Algorithm)

            => Algorithm == AlfenAlgorithm
                   ? alfenSuite
                   : SignatureSuites.TryGet(Algorithm);

        #endregion

        #region EnsureIdentity()

        /// <summary>
        /// Make the meter's own key if it has none, and say whether one was
        /// made.
        /// </summary>
        /// <remarks>
        /// Called at every start and does nothing after the first: a meter that
        /// made a new identity whenever it came up would invalidate every
        /// reading it had ever signed.
        /// </remarks>
        public MeterKey? EnsureIdentity()
        {

            lock (cacheLock)
            {
                if (keys.Count > 0)
                    return null;
            }

            var key = Create(DefaultAlgorithm, "the identity of this meter, made at its first start");

            SetDefault(key.Id, out _);

            return key;

        }

        #endregion

        #region Create(Algorithm, Note = null)

        /// <summary>
        /// Make a new key.
        /// </summary>
        /// <param name="Algorithm">Which signature suite it belongs to.</param>
        /// <param name="Note">A line to remember what it is for.</param>
        /// <exception cref="ArgumentException">When the algorithm is not one this meter knows.</exception>
        public MeterKey Create(String   Algorithm,
                               String?  Note   = null)
        {

            var suite = SuiteFor(Algorithm)
                            ?? throw new ArgumentException($"Unknown signature algorithm '{Algorithm}'!", nameof(Algorithm));

            var now   = TimeProvider.GetUtcNow();
            var id    = NewId(now);
            var pair  = suite.GenerateKeyPair();

            var key   = new MeterKey(id, Algorithm, now, pair.PublicKey, pair.PrivateKey, Note);

            Write(key);

            lock (cacheLock)
            {

                keys[id] = key;

                // The first key of an empty store is the identity by default:
                // a store with keys in it and none of them the identity is a
                // meter that cannot sign anything.
                if (!keys.Values.Any(candidate => candidate.IsDefault))
                    key.IsDefault = true;

            }

            OnChanged?.Invoke(key, "made");

            return key;

        }

        #endregion

        #region SetDefault(Id, out Error)

        /// <summary>
        /// Make the given key the one this meter signs with when nobody names
        /// one.
        /// </summary>
        public Boolean SetDefault(String                          Id,
                                  [NotNullWhen(false)] out String?  Error)
        {

            MeterKey? chosen;

            lock (cacheLock)
            {

                if (!keys.TryGetValue(Id, out chosen))
                {
                    Error = $"There is no signing key '{Id}'.";
                    return false;
                }

                foreach (var key in keys.Values)
                    key.IsDefault = key.Id == Id;

            }

            foreach (var key in Keys)
                Write(key);

            Error = null;
            OnChanged?.Invoke(chosen, "made the identity");
            return true;

        }

        #endregion

        #region TryRemove(Id, out Error)

        /// <summary>
        /// Throw a key away, with its private half.
        /// </summary>
        /// <remarks>
        /// Everything this key ever signed becomes uncheckable, which is why
        /// the last one cannot go: a meter with no signing key can still
        /// measure, and nothing it measures can be shown to have come from it.
        /// </remarks>
        public Boolean TryRemove(String                            Id,
                                 [NotNullWhen(false)] out String?  Error)
        {

            lock (cacheLock)
            {

                if (!keys.TryGetValue(Id, out var key))
                {
                    Error = $"There is no signing key '{Id}'.";
                    return false;
                }

                if (keys.Count <= 1)
                {
                    Error = "This is the only signing key of this meter. Make another one first - " +
                            "without one it can measure, and nothing it measures can be shown to have come from it.";
                    return false;
                }

                try
                {
                    var directory = System.IO.Path.Combine(Path, Id);

                    if (Directory.Exists(directory))
                        Directory.Delete(directory, recursive: true);
                }
                catch (Exception e)
                {
                    Error = $"'{Id}' could not be removed: {e.Message}";
                    return false;
                }

                keys.Remove(Id);

                // Whatever else happens, this store does not end up with keys
                // and no identity among them.
                if (key.IsDefault)
                {

                    var next = keys.Values.OrderBy(candidate => candidate.Id).First();

                    next.IsDefault = true;
                    Write(next);

                }

            }

            Error = null;
            OnChanged?.Invoke(null, $"'{Id}' removed");
            return true;

        }

        #endregion

        #region Get(Id) / Sign(Key, Message, Options = null)

        /// <summary>
        /// The key of the given id, the identity when the id is empty, or null
        /// when there is no such key.
        /// </summary>
        public MeterKey? Get(String? Id)
        {

            if (String.IsNullOrWhiteSpace(Id))
                return Default;

            lock (cacheLock)
                return keys.GetValueOrDefault(Id.Trim());

        }

        /// <summary>
        /// Sign something with the given key.
        /// </summary>
        /// <param name="Key">One of this store's keys.</param>
        /// <param name="Message">What to sign - the message itself, unless the options say it is already a digest.</param>
        /// <param name="Options">How to sign it, e.g. which signature layout.</param>
        public Byte[] Sign(MeterKey            Key,
                           ReadOnlySpan<Byte>  Message,
                           SignatureOptions?   Options   = null)
        {

            var suite = SuiteFor(Key.Algorithm)
                            ?? throw new InvalidOperationException($"The key '{Key.Id}' names an algorithm this meter no longer knows: '{Key.Algorithm}'.");

            return suite.Sign(Message, Key.PrivateKey, Options);

        }

        #endregion


        #region (private) Write(Key) / Reload()

        private void Write(MeterKey Key)
        {

            var directory = System.IO.Path.Combine(Path, Key.Id);

            Directory.CreateDirectory(directory);

            WritePrivateFile(
                System.IO.Path.Combine(directory, "private.key"),
                Convert.ToHexString(Key.PrivateKey)
            );

            File.WriteAllText(
                System.IO.Path.Combine(directory, "meta.json"),
                Key.MetadataJSON().ToString()
            );

        }

        private void Reload()
        {

            lock (cacheLock)
            {

                keys.Clear();

                foreach (var directory in Directory.GetDirectories(Path))
                {

                    try
                    {

                        var metaPath     = System.IO.Path.Combine(directory, "meta.json");
                        var privatePath  = System.IO.Path.Combine(directory, "private.key");

                        if (!File.Exists(metaPath) || !File.Exists(privatePath))
                            continue;

                        var meta         = JObject.Parse(File.ReadAllText(metaPath));

                        var id           = meta["id"]?.Value<String>();
                        var algorithm    = meta["algorithm"]?.Value<String>();
                        var publicKey    = meta["publicKey"]?.Value<String>();

                        if (id is null || algorithm is null || publicKey is null)
                            continue;

                        var key = new MeterKey(
                                      id,
                                      algorithm,
                                      Moment(meta["createdAt"]),
                                      Convert.FromHexString(publicKey),
                                      Convert.FromHexString(File.ReadAllText(privatePath).Trim()),
                                      meta["note"]?.Type == JTokenType.String ? meta["note"]!.Value<String>() : null
                                  ) {
                                      IsDefault = meta["isDefault"]?.Value<Boolean>() ?? false
                                  };

                        keys[id] = key;

                    }
                    catch (Exception e)
                    {
                        // One unreadable key is not a reason to come up without
                        // the others, but it is a reason to say so.
                        LastError = $"The signing key in '{directory}' could not be read: {e.Message}";
                    }

                }

            }

        }

        #endregion

        #region (private static) helpers

        /// <summary>
        /// A timestamp out of JSON, read from its text.
        /// </summary>
        /// <remarks>
        /// Not <c>Value&lt;DateTimeOffset&gt;()</c>: Newtonsoft may already have
        /// turned the string into a <c>DateTime</c> while parsing, and asking
        /// such a token for a DateTimeOffset throws - which would drop the key
        /// and leave a restarted meter unable to check what it had signed.
        /// </remarks>
        private static DateTimeOffset Moment(JToken? Token)

            => Token is not null &&
               DateTimeOffset.TryParse(Token.ToString(), null,
                                       System.Globalization.DateTimeStyles.RoundtripKind, out var moment)
                   ? moment
                   : DateTimeOffset.MinValue;

        private String NewId(DateTimeOffset Now)

            => $"{Now:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}";

        /// <summary>
        /// Write something only this process's user may read.
        /// </summary>
        private static void WritePrivateFile(String Path, String Content)
        {

            File.WriteAllText(Path, Content);

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// Every key of this store, and what a request may ask for.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("keys",        new JArray(Keys.Select(key => key.ToJSON()))),
                   new JProperty("algorithms",  new JArray(Algorithms)),
                   LastError is not null
                       ? new JProperty("error", LastError)
                       : new JProperty("error", JValue.CreateNull())
               );

        #endregion

    }

}
