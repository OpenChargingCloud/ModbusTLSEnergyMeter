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

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// Why a charging session was not begun or not ended.
    /// </summary>
    /// <param name="Kind">What kind of no it is.</param>
    /// <param name="Why">In words.</param>
    public sealed record SessionRefusal(SessionRefusalKind  Kind,
                                        String              Why);


    /// <summary>
    /// What a command came to: what it did, or why not.
    /// </summary>
    public sealed record SessionAnswer<T>(T?               Value,
                                          SessionRefusal?  Refusal)
        where T : class
    {

        public static SessionAnswer<T> Done(T Value)
            => new (Value, null);

        public static SessionAnswer<T> Refused(SessionRefusalKind  Kind,
                                               String              Why)
            => new (null, new SessionRefusal(Kind, Why));

    }


    /// <summary>
    /// A session that was begun, and the key it will be signed with.
    /// </summary>
    public sealed record StartedSession(ChargingSession  Session,
                                        MeterKey         Key);


    /// <summary>
    /// What this meter says about itself in every OCMF document it signs: as
    /// the gateway that signs, and about the meter that measured - which are
    /// one device while it measures with its own simulation, and two once it
    /// stands in front of another meter.
    /// </summary>
    /// <param name="SerialNumber">The serial number of the gateway, OCMF "GS".</param>
    /// <param name="Version">The version of this software, OCMF "GV".</param>
    /// <param name="Model">What the meter that measured is called, OCMF "MM".</param>
    /// <param name="Vendor">Who made it, OCMF "MV".</param>
    /// <param name="MeterSerialNumber">Its serial number, OCMF "MS"; the gateway's where null.</param>
    /// <param name="MeterFirmware">Its firmware, OCMF "MF"; this software's version where null.</param>
    public sealed record MeterDescription(String   SerialNumber,
                                          String   Version,
                                          String   Model,
                                          String   Vendor             = "Vanaheimr",
                                          String?  MeterSerialNumber  = null,
                                          String?  MeterFirmware      = null);


    /// <summary>
    /// Begins and ends the charging sessions of this meter, whoever asks: a
    /// person on the JSON API, or a charging station on the session model.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One place for both doors, so that what a session is - the reading it
    /// began at, the key it is signed with, who charged, the document it ends
    /// in - does not depend on which door it came through. A session begun over
    /// Modbus can be ended on the web page and the other way round, and either
    /// way it ends in the same document.
    /// </para>
    /// <para>
    /// One command at a time. Two stops arriving together would otherwise both
    /// read the counter, and the second would find no session and say so after
    /// the first had already taken it.
    /// </para>
    /// </remarks>
    public sealed class SessionSigner
    {

        #region Data

        private readonly SemaphoreSlim                          gate = new (1, 1);
        private readonly Func<Task<Decimal>>                    importedWh;
        private readonly Func<MeterDescription>                 description;
        private readonly Func<Boolean>                          clockIsSynchronised;
        private readonly Action                                 saveCounters;

        #endregion

        #region Properties

        /// <summary>The sessions, the counters, and the last document.</summary>
        public ChargingSessions  Sessions  { get; }

        /// <summary>The keys sessions are signed with.</summary>
        public MeterKeyStore     Keys      { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Begin and end the charging sessions of a meter.
        /// </summary>
        /// <param name="Sessions">The sessions, the counters, and the last document.</param>
        /// <param name="Keys">The keys sessions are signed with.</param>
        /// <param name="ImportedWh">What the imported energy counter stands at, in Wh - or an EnergyUnreadable saying why not.</param>
        /// <param name="Description">What the meter says about itself in a document.</param>
        /// <param name="ClockIsSynchronised">Whether a time server has answered.</param>
        /// <param name="SaveCounters">Write the energy counters down, at both ends of a session.</param>
        public SessionSigner(ChargingSessions        Sessions,
                             MeterKeyStore           Keys,
                             Func<Task<Decimal>>     ImportedWh,
                             Func<MeterDescription>  Description,
                             Func<Boolean>           ClockIsSynchronised,
                             Action                  SaveCounters)
        {

            this.Sessions             = Sessions;
            this.Keys                 = Keys;
            this.importedWh           = ImportedWh;
            this.description          = Description;
            this.clockIsSynchronised  = ClockIsSynchronised;
            this.saveCounters         = SaveCounters;

        }

        #endregion


        #region ReadImportedWh()

        /// <summary>
        /// What the imported energy counter stands at, in Wh.
        /// </summary>
        /// <exception cref="EnergyUnreadable">With why.</exception>
        public Task<Decimal> ReadImportedWh()

            => importedWh();

        #endregion

        #region Start(Parameters, Key = null)

        /// <summary>
        /// Begin a charging session, to be signed with the given key or with
        /// this meter's identity.
        /// </summary>
        public async Task<SessionAnswer<StartedSession>> Start(SessionParameters  Parameters,
                                                               MeterKey?          Key   = null)
        {

            var parameters = Parameters.Trimmed();

            if (!parameters.IsValid(out var invalid))
                return SessionAnswer<StartedSession>.Refused(SessionRefusalKind.InvalidParameter, invalid);

            var key = Key ?? Keys.Get(null);

            if (key is null)
                return SessionAnswer<StartedSession>.Refused(SessionRefusalKind.NoKey, "This meter has no signing key at all.");

            if (OCMFWriter.AlgorithmFor(key.Algorithm) is null)
                return SessionAnswer<StartedSession>.Refused(SessionRefusalKind.NoKey,
                                                             $"OCMF has no name for '{key.Algorithm}', so a document cannot say what it was signed with. " +
                                                             $"Sign with one of: {String.Join(", ", OCMFWriter.SigningAlgorithms)}.");

            await gate.WaitAsync();

            try
            {

                Decimal wh;

                try
                {
                    wh = await importedWh();
                }
                catch (EnergyUnreadable e)
                {
                    return SessionAnswer<StartedSession>.Refused(SessionRefusalKind.Unreadable, e.Message);
                }

                if (!Sessions.TryStart(wh / 1000m, key.Id, parameters, out var session, out var problem))
                    return SessionAnswer<StartedSession>.Refused(SessionRefusalKind.AlreadyRunning, problem);

                // The session's start reading is now on disk; the counter it was
                // taken from goes down beside it, so that a crash in between
                // cannot leave a session starting at a reading this meter no
                // longer stands at.
                saveCounters();

                return SessionAnswer<StartedSession>.Done(new StartedSession(session, key));

            }
            finally
            {
                gate.Release();
            }

        }

        #endregion

        #region Stop(StationSessionId = null)

        /// <summary>
        /// End the charging session that is running, into one signed document -
        /// the one the given session id names, when one is given.
        /// </summary>
        /// <remarks>
        /// One document and not two, because that is what makes it a charging
        /// session: two separately signed readings are two facts about a meter,
        /// and the energy between them is an inference somebody else has to be
        /// trusted to have drawn correctly. Here the subtraction is inside what
        /// was signed.
        /// </remarks>
        public async Task<SessionAnswer<SignedSession>> Stop(String? StationSessionId = null)
        {

            await gate.WaitAsync();

            try
            {

                Decimal wh;

                try
                {
                    wh = await importedWh();
                }
                catch (EnergyUnreadable e)
                {
                    return SessionAnswer<SignedSession>.Refused(SessionRefusalKind.Unreadable, e.Message);
                }

                var stopValue = wh / 1000m;

                // Looked at before the session is taken away, so that a refusal
                // leaves it running rather than losing it.
                if (Sessions.Current is ChargingSession open)
                {

                    if (!String.IsNullOrWhiteSpace(StationSessionId) &&
                        open.Parameters.StationSessionId != StationSessionId.Trim())
                    {
                        return SessionAnswer<SignedSession>.Refused(SessionRefusalKind.NotThisSession,
                                                                    $"The session running here is '{open.Parameters.StationSessionId ?? "(none given)"}', " +
                                                                    $"not '{StationSessionId.Trim()}'. It is still running.");
                    }

                    if (stopValue < open.StartValue)
                        return SessionAnswer<SignedSession>.Refused(SessionRefusalKind.CounterBackwards,
                                                                    $"This session started at {open.StartValue} kWh and the meter now stands at " +
                                                                    $"{stopValue} kWh, so stopping it would report less energy than none. " +
                                                                     "The counter has gone backwards - cleared, or lost further than the last time " +
                                                                     "it was written down. The session is still running and can be stopped once the " +
                                                                     "counter passes where it began.");

                }

                if (!Sessions.TryStop(out var session, out var problem))
                    return SessionAnswer<SignedSession>.Refused(SessionRefusalKind.NotRunning, problem);

                // The key the session began with, not whatever is the identity
                // now: a document whose two readings were signed by different
                // keys is not one document.
                var key = Keys.Get(session.KeyId);

                if (key is null)
                    return SessionAnswer<SignedSession>.Refused(SessionRefusalKind.NoKey,
                                                                $"The key '{session.KeyId}' this session was started with is gone, " +
                                                                 "so the session cannot be signed as one document.");

                var now = Sessions.TimeProvider.GetUtcNow();

                try
                {

                    var document = OCMFWriter.Build(
                                       Keys,
                                       key,
                                       Payload($"T{Sessions.NextTransaction()}", session.Parameters),
                                       [
                                           Reading(session.StartedAt, session.StartValue, "B"),
                                           Reading(now,               stopValue,          "E")
                                       ]
                                   );

                    saveCounters();

                    var (publicKey, encoding) = MeterPublicKey.ForOCMF(key);

                    var signed = new SignedSession(
                                     session.Id,
                                     session.Parameters.StationSessionId,
                                     session.StartedAt,
                                     now,
                                     session.StartValue,
                                     stopValue,
                                     document,
                                     key.Id,
                                     publicKey,
                                     encoding
                                 );

                    Sessions.Keep(signed);

                    return SessionAnswer<SignedSession>.Done(signed);

                }
                catch (Exception e)
                {
                    return SessionAnswer<SignedSession>.Refused(SessionRefusalKind.SigningFailed,
                                                                $"That session could not be signed: {e.Message}");
                }

            }
            finally
            {
                gate.Release();
            }

        }

        #endregion


        #region Payload(Pagination, Parameters = null)

        /// <summary>
        /// Everything an OCMF document says about the meter it came from, and
        /// about the session when it is one.
        /// </summary>
        public JObject Payload(String              Pagination,
                               SessionParameters?  Parameters   = null)
        {

            var meter   = description();

            var payload = new JObject(

                              // "TT" came with 1.1; a document carrying one says
                              // it is of a version that has it.
                              new JProperty("FV",  Parameters?.TariffText is not null ? "1.1" : "1.0"),

                              // The gateway and the meter are the same device
                              // here, and saying so twice is what the format
                              // expects rather than a mistake.
                              new JProperty("GI",  "Vanaheimr ModbusTLSEnergyMeter"),
                              new JProperty("GS",  meter.SerialNumber),
                              new JProperty("GV",  meter.Version),

                              new JProperty("PG",  Pagination),

                              new JProperty("MV",  meter.Vendor),
                              new JProperty("MM",  meter.Model),
                              new JProperty("MS",  meter.MeterSerialNumber ?? meter.SerialNumber),
                              new JProperty("MF",  meter.MeterFirmware     ?? meter.Version)

                          );

            // Absent rather than false when nobody was identified: "IS": false
            // says the meter looked and found nobody, which is a different claim
            // from a reading that was never about a person.
            if (Parameters?.Identification is String identification)
            {
                payload.Add("IS",  true);
                payload.Add("IT",  Parameters.IdentificationType ?? "UNDEFINED");
                payload.Add("ID",  identification);
            }
            else
            {
                payload.Add("IS",  false);
                if (Parameters?.IdentificationType is String type)
                    payload.Add("IT",  type);
            }

            if (Parameters?.TariffText is String tariff)
                payload.Add("TT",  tariff);

            if (Parameters?.ChargePointIdType is String chargePointIdType &&
                Parameters.ChargePointId      is String chargePointId)
            {
                payload.Add("CT",  chargePointIdType);
                payload.Add("CI",  chargePointId);
            }

            return payload;

        }

        #endregion

        #region Reading(Timestamp, Value, Transaction)

        /// <summary>
        /// One reading, with the letter that says how far this meter's clock can
        /// be trusted.
        /// </summary>
        /// <remarks>
        /// "S" only when a time server actually answered. A meter that claimed a
        /// synchronised clock it does not have would be lying about the one
        /// thing a reading cannot be checked against afterwards.
        /// </remarks>
        public OCMFReadingToWrite Reading(DateTimeOffset  Timestamp,
                                          Decimal         Value,
                                          String?         Transaction)

            => new (
                   Timestamp,
                   Value,
                   Transaction,
                   TimeSync:  clockIsSynchronised() ? "S" : "I"
               );

        #endregion

    }

}
