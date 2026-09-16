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

using cloud.charging.open.chargy;
using cloud.charging.open.chargy.Crypto;
using cloud.charging.open.chargy.Formats.Alfen;
using cloud.charging.open.chargy.Formats.OCMF;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The keys this meter signs with, and whether what it signs can be
    /// checked.
    /// </summary>
    /// <remarks>
    /// Every one of these is a round trip through ChargyCore rather than
    /// through anything written here. A test that verified this meter's OCMF
    /// with this meter's own code would pass just as happily if both ends
    /// agreed on the same mistake - the wrong signature encoding, the wrong
    /// public key wrapper, a timestamp in a shape no reader accepts - and every
    /// one of those produces a document that looks correct and reads as a
    /// forgery.
    /// </remarks>
    public class SigningTests
    {

        #region Data

        private String?  workingDirectory;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            workingDirectory = Path.Combine(
                                   Path.GetTempPath(),
                                   "ModbusTLSEnergyMeterTests",
                                   Guid.NewGuid().ToString("N")
                               );

            Directory.CreateDirectory(workingDirectory);

        }

        [TearDown]
        public void TearDown()
        {

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file still held is not what is under test */ }
            }

        }

        #endregion


        #region AMeterMakesItselfAnIdentity_Once()

        /// <summary>
        /// The first start makes one key; every start after it makes none.
        /// </summary>
        /// <remarks>
        /// A meter that made a new identity whenever it came up would invalidate
        /// every reading it had ever signed, and would do it silently.
        /// </remarks>
        [Test]
        public void AMeterMakesItselfAnIdentity_Once()
        {

            var path   = Path.Combine(workingDirectory!, "keys");

            var first  = new MeterKeyStore(path);
            var made   = first.EnsureIdentity();

            Assert.Multiple(() => {
                Assert.That(made,                  Is.Not.Null);
                Assert.That(made!.Algorithm,       Is.EqualTo(MeterKeyStore.DefaultAlgorithm));
                Assert.That(made.IsDefault,        Is.True);
                Assert.That(first.Keys.Count(),    Is.EqualTo(1));
            });

            // The same store again, as a restart sees it.
            var again  = new MeterKeyStore(path);

            Assert.Multiple(() => {

                Assert.That(again.EnsureIdentity(), Is.Null,  "a restart must not make a second identity");
                Assert.That(again.Keys.Count(),     Is.EqualTo(1));

                // And it is the same key, not a new one that happens to be alone.
                Assert.That(again.Default?.Id,          Is.EqualTo(made!.Id));
                Assert.That(again.Default?.PublicKeyHEX, Is.EqualTo(made.PublicKeyHEX));

            });

        }

        #endregion

        #region AKeyStillSigns_AfterARestart()

        /// <summary>
        /// The private half survives a restart, which is the only thing that
        /// makes an identity an identity.
        /// </summary>
        [Test]
        public void AKeyStillSigns_AfterARestart()
        {

            var path    = Path.Combine(workingDirectory!, "keys");
            var before  = new MeterKeyStore(path);
            var key     = before.EnsureIdentity()!;

            var after   = new MeterKeyStore(path);
            var same    = after.Get(key.Id);

            Assert.That(same, Is.Not.Null, "the key should have been read back");

            var document = OCMFOf(after, same!, 42.5m);

            Assert.That(Verify(document, same!), Is.EqualTo(VerificationResult.ValidSignature));

        }

        #endregion

        #region TheLastKeyCannotBeRemoved()

        /// <summary>
        /// A meter with no signing key can still measure, and nothing it
        /// measures can be shown to have come from it.
        /// </summary>
        [Test]
        public void TheLastKeyCannotBeRemoved()
        {

            var store = new MeterKeyStore(Path.Combine(workingDirectory!, "keys"));
            var first = store.EnsureIdentity()!;

            Assert.Multiple(() => {
                Assert.That(store.TryRemove(first.Id, out var error), Is.False);
                Assert.That(error,                                    Does.Contain("only signing key"));
            });

            var second = store.Create("Ed25519", "a second one");

            Assert.Multiple(() => {

                Assert.That(store.TryRemove(first.Id, out _), Is.True, "now that there are two, either may go");

                // And removing the identity hands the title on rather than
                // leaving a store with keys and no identity among them.
                Assert.That(store.Default?.Id,   Is.EqualTo(second.Id));
                Assert.That(store.Keys.Count(),  Is.EqualTo(1));

            });

        }

        #endregion

        #region EveryAlgorithm_ProducesAnOCMFDocumentChargyVerifies(Algorithm)

        /// <summary>
        /// The point of all of it: whatever this meter signs an OCMF document
        /// with, ChargyCore reads it back and says the signature is good.
        /// </summary>
        /// <remarks>
        /// One case per algorithm, because they do not fail together. The ECDSA
        /// ones carry a DER signature and a SubjectPublicKeyInfo; EdDSA and
        /// ML-DSA carry an opaque signature over the payload itself and a raw
        /// public key. Getting either pair the wrong way round produces a
        /// document that is signed correctly and reads as invalid.
        /// </remarks>
        [TestCase("ECDSA-P256")]
        [TestCase("ECDSA-P384")]
        [TestCase("ECDSA-P521")]
        [TestCase("ECDSA-secp256k1")]
        [TestCase("ECDSA-secp192r1")]
        [TestCase("Ed25519")]
        [TestCase("Ed448")]
        [TestCase("ML-DSA-44")]
        [TestCase("ML-DSA-65")]
        [TestCase("ML-DSA-87")]
        public void EveryAlgorithm_ProducesAnOCMFDocumentChargyVerifies(String Algorithm)
        {

            var store    = new MeterKeyStore(Path.Combine(workingDirectory!, "keys"));
            var key      = store.Create(Algorithm);

            var document = OCMFOf(store, key, 1234.567m);

            Assert.That(document, Does.StartWith("OCMF|"));

            Assert.That(Verify(document, key),
                        Is.EqualTo(VerificationResult.ValidSignature),
                        $"a document signed with {Algorithm} should verify");

        }

        #endregion

        #region AChangedDocument_StopsVerifying()

        /// <summary>
        /// A signature that verified whatever the payload said would not be
        /// worth computing.
        /// </summary>
        [Test]
        public void AChangedDocument_StopsVerifying()
        {

            var store     = new MeterKeyStore(Path.Combine(workingDirectory!, "keys"));
            var key       = store.EnsureIdentity()!;

            var document  = OCMFOf(store, key, 1000m);
            var tampered  = document.Replace("1000.0", "9999.0");

            Assert.That(tampered, Is.Not.EqualTo(document), "the test needs the reading to actually change");

            Assert.That(Verify(tampered, key), Is.EqualTo(VerificationResult.InvalidSignature));

        }

        #endregion

        #region ADocumentIsNotVerifiedByAnotherMetersKey()

        /// <summary>
        /// Two meters, and the reading of one does not check out against the
        /// other.
        /// </summary>
        [Test]
        public void ADocumentIsNotVerifiedByAnotherMetersKey()
        {

            var ours    = new MeterKeyStore(Path.Combine(workingDirectory!, "ours"));
            var theirs  = new MeterKeyStore(Path.Combine(workingDirectory!, "theirs"));

            var ourKey    = ours.  EnsureIdentity()!;
            var theirKey  = theirs.EnsureIdentity()!;

            var document  = OCMFOf(ours, ourKey, 17m);

            Assert.Multiple(() => {
                Assert.That(Verify(document, ourKey),   Is.EqualTo(VerificationResult.ValidSignature));
                Assert.That(Verify(document, theirKey), Is.EqualTo(VerificationResult.InvalidSignature));
            });

        }

        #endregion

        #region TheTimestampHasTheShapeOCMFInsistsOn()

        /// <summary>
        /// A comma before exactly three milliseconds, an offset with no colon,
        /// and one letter for how far the clock can be trusted.
        /// </summary>
        /// <remarks>
        /// None of that is what "o" or "s" produces, and a timestamp in any
        /// other shape makes the whole reading unreadable rather than merely
        /// oddly formatted.
        /// </remarks>
        [Test]
        public void TheTimestampHasTheShapeOCMFInsistsOn()
        {

            var moment = new DateTimeOffset(2026, 9, 16, 8, 57, 44, 337, TimeSpan.Zero);

            Assert.That(OCMFWriter.Timestamp(moment, "S"),
                        Is.EqualTo("2026-09-16T08:57:44,337+0000 S"));

            Assert.That(OCMFWriter.Timestamp(moment.ToOffset(TimeSpan.FromHours(2)), "I"),
                        Is.EqualTo("2026-09-16T10:57:44,337+0200 I"));

        }

        #endregion


        #region AnAlfenRecord_IsWhatTheReaderWouldRebuildAndSign()

        /// <summary>
        /// The 82 bytes in the right order, the key compressed, the signature a
        /// bare r and s - established one link at a time, because the Alfen
        /// layout has no separators and no field names, and one value written a
        /// byte to the left of where it belongs produces a record that parses,
        /// reads plausibly, and fails its signature.
        /// </summary>
        /// <remarks>
        /// Four links, and a fifth deliberately absent. ChargyCore parses the
        /// record; every field comes back as it went in; the buffer its verifier
        /// would rebuild from those fields is byte for byte the one that was
        /// signed; and the signature checks out over that buffer with the curve
        /// and the suite ChargyCore itself would use.
        ///
        /// What is not asserted is the last hop through AlfenCrypt01, and not
        /// because anything written here fails it. Its VerifyMeasurement needs
        /// the back-reference from a reading to its measurement, which the Alfen
        /// parse path leaves null - so it answers "Not an Alfen measurement!"
        /// for every freshly parsed record, whoever wrote it. The property is
        /// internal to ChargyCore, so nothing out here can set it either.
        /// </remarks>
        [Test]
        public void AnAlfenRecord_IsWhatTheReaderWouldRebuildAndSign()
        {

            var store   = new MeterKeyStore(Path.Combine(workingDirectory!, "keys"));
            var key     = store.Create(MeterKeyStore.AlfenAlgorithm);

            var record  = AlfenWriter.Build(
                              store,
                              key,
                              new DateTimeOffset(2026, 9, 16, 10, 0, 0, TimeSpan.Zero),
                              Value:                    123456,
                              Scale:                    0,
                              MeterId:                  "0102030405060708090A",
                              AdapterId:                "0A0B0C0D0E0F10111213",
                              AdapterFirmware:          "v1.0",
                              AdapterFirmwareChecksum:  "ABCD",
                              OBIS:                     "1-0:1.8.0",
                              Transaction:              "B",
                              SecondsIndex:             1000,
                              SessionId:                7,
                              Pagination:               1,
                              Authorization:            "TESTTAG01"
                          );

            #region It is six fields of the lengths the format prescribes

            Assert.That(record, Does.StartWith("AP;0;3;"));

            var fields = record.Split(';');

            Assert.Multiple(() => {
                Assert.That(fields[3].FromBASE32().Length, Is.EqualTo(25), "the public key is 25 bytes");
                Assert.That(fields[4].FromBASE32().Length, Is.EqualTo(82), "the data set is 82 bytes");
                Assert.That(fields[5].FromBASE32().Length, Is.EqualTo(48), "the signature is 48 bytes");
            });

            #endregion

            #region ChargyCore reads it back, and reads back what went in

            var parsed = new AlfenFormat(I18NDictionary.Default()).TryParseText(record);

            Assert.That(parsed, Is.InstanceOf<ChargeTransparencyRecord>(),
                        $"ChargyCore should read this back: {(parsed as SessionCryptoResult)?.Message?.ToString() ?? parsed.ToString()}");

            var session      = ((ChargeTransparencyRecord) parsed).ChargingSessions.First();
            var measurement  = session.Measurements.First();
            var alfen        = (AlfenMeasurement) measurement;
            var value        = measurement.Values.First();
            var mine         = fields[4].FromBASE32();

            Assert.Multiple(() => {
                Assert.That(alfen.AdapterId,                 Is.EqualTo("0a0b0c0d0e0f10111213"));
                Assert.That(alfen.AdapterFWVersion,          Is.EqualTo("v1.0"));
                Assert.That(alfen.EnergyMeterId,             Is.EqualTo("0102030405060708090a"));
                Assert.That(alfen.OBIS,                      Is.EqualTo("1-0:1.8.0*0"));
                Assert.That(alfen.UnitEncoded,               Is.EqualTo(30),     "30 is Wh");
                Assert.That(value.Value,                     Is.EqualTo(123456));
                Assert.That(value.SecondsIndex,              Is.EqualTo(1000));
                Assert.That(session.AuthorizationStart?.Id,  Is.EqualTo("TESTTAG01"));
                Assert.That(session.InternalSessionId,       Is.EqualTo("7"));
            });

            #endregion

            #region The buffer its verifier would rebuild is the one that was signed

            // Assembled exactly as AlfenCrypt01 assembles it, from the values it
            // would have. One byte of difference here would fail the signature
            // for a reason that has nothing to do with the meter being honest.
            var theirs = new Byte[82];

            ChargyLib.SetHex        (theirs, alfen.AdapterId,                            0);
            ChargyLib.SetText       (theirs, alfen.AdapterFWVersion,                    10);
            ChargyLib.SetHex        (theirs, alfen.AdapterFWChecksum,                   14);
            ChargyLib.SetHex        (theirs, alfen.EnergyMeterId,                       16);
            ChargyLib.SetHex        (theirs, value.StatusMeter   ?? "",                 26, true);
            ChargyLib.SetHex        (theirs, value.StatusAdapter ?? "",                 28, true);
            ChargyLib.SetUInt32     (theirs, (UInt32) (value.SecondsIndex ?? 0),        30, true);
            ChargyLib.SetTimestamp32(theirs, value.Timestamp,                           34, AddMeterOffset: false);
            ChargyLib.SetHex        (theirs, ChargyLib.OBIS2Hex(alfen.OBIS ?? ""),      38);
            ChargyLib.SetInt8       (theirs, alfen.UnitEncoded ?? 0,                    44);
            ChargyLib.SetInt8       (theirs, alfen.Scale,                               45);
            ChargyLib.SetUInt64     (theirs, value.Value,                               46, true);
            ChargyLib.SetText       (theirs, session.AuthorizationStart?.Id ?? "",      54);
            ChargyLib.SetUInt32     (theirs, UInt32.Parse(session.InternalSessionId!),  74, true);
            ChargyLib.SetUInt32     (theirs, UInt32.Parse(value.PaginationId!),         78, true);

            Assert.That(mine, Is.EqualTo(theirs), "the reader would rebuild exactly the bytes that were signed");

            #endregion

            #region And the signature checks out over them

            var suite = MeterKeyStore.SuiteFor(MeterKeyStore.AlfenAlgorithm)!;

            Assert.That(
                suite.Verify(
                    System.Security.Cryptography.SHA256.HashData(theirs),
                    fields[5].FromBASE32(),
                    MeterPublicKey.ForAlfen(key),
                    // Both halves of s turn up in the field, so the reader
                    // accepts either and so does this.
                    new SignatureOptions(Prehashed: true, LowS: false)
                ),
                Is.True
            );

            #endregion

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// One fiscal reading, signed.
        /// </summary>
        private static String OCMFOf(MeterKeyStore  Store,
                                     MeterKey       Key,
                                     Decimal        Value)

            => OCMFWriter.Build(
                   Store,
                   Key,
                   new JObject(
                       new JProperty("FV",  "1.0"),
                       new JProperty("GI",  "Vanaheimr ModbusTLSEnergyMeter"),
                       new JProperty("GS",  "meter-test-001"),
                       new JProperty("MV",  "Vanaheimr"),
                       new JProperty("MM",  "DemoMeter-3P"),
                       new JProperty("MS",  "meter-test-001"),
                       new JProperty("PG",  "F1")
                   ),
                   [
                       new OCMFReadingToWrite(
                           new DateTimeOffset(2026, 9, 16, 10, 0, 0, TimeSpan.Zero),
                           Value,
                           null
                       )
                   ]
               );

        /// <summary>
        /// What ChargyCore makes of a document, checked against the public key
        /// in the shape that document's algorithm wants it.
        /// </summary>
        private static VerificationResult Verify(String    Document,
                                                 MeterKey  Key)
        {

            var scanned = new OCMFDocumentScanner().Scan([ Document ]);

            if (scanned.Documents.Count == 0)
                return VerificationResult.UnknownSignatureFormat;

            var (publicKey, encoding) = MeterPublicKey.ForOCMF(Key);

            return new OCMFSignatureValidator(I18NDictionary.Default()).
                       Validate(scanned.Documents[0], publicKey, encoding);

        }

        #endregion

    }

}
