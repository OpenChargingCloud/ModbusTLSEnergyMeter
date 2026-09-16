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
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// A charging session this meter is measuring, from the reading it started
    /// at to the reading it ended at.
    /// </summary>
    /// <param name="Id">What this session is called.</param>
    /// <param name="StartedAt">When it began.</param>
    /// <param name="StartValue">What the meter stood at then, in kWh.</param>
    /// <param name="KeyId">The key the whole session will be signed with.</param>
    /// <param name="Identification">Who started it, when anybody said.</param>
    /// <param name="IdentificationType">How they were identified, e.g. "ISO14443".</param>
    public class ChargingSession(String          Id,
                                 DateTimeOffset  StartedAt,
                                 Decimal         StartValue,
                                 String          KeyId,
                                 String?         Identification       = null,
                                 String?         IdentificationType   = null)
    {

        #region Properties

        /// <summary>What this session is called.</summary>
        public String          Id                  { get; } = Id;

        /// <summary>When it began.</summary>
        public DateTimeOffset  StartedAt           { get; } = StartedAt;

        /// <summary>What the meter stood at then, in kWh.</summary>
        public Decimal         StartValue          { get; } = StartValue;

        /// <summary>
        /// The key the whole session is signed with.
        /// </summary>
        /// <remarks>
        /// Pinned when the session starts rather than looked up when it stops.
        /// A session whose start reading was signed by one key and whose stop
        /// reading was signed by another is not one document and cannot be made
        /// into one.
        /// </remarks>
        public String          KeyId               { get; } = KeyId;

        /// <summary>Who started it, when anybody said.</summary>
        public String?         Identification      { get; } = Identification;

        /// <summary>How they were identified.</summary>
        public String?         IdentificationType  { get; } = IdentificationType;

        #endregion

        #region (internal) StoredJSON() / TryParse(JSON, out Session)

        /// <summary>
        /// The session as it is kept on disk while it runs.
        /// </summary>
        /// <remarks>
        /// More than <see cref="ToJSON"/> gives out: the identification type
        /// goes in as well, because the document written at the end has to say
        /// how the person was identified and a restart must not lose that.
        /// </remarks>
        internal JObject StoredJSON()

            => new (
                   new JProperty("id",                  Id),
                   new JProperty("startedAt",           StartedAt.UtcDateTime.ToString("o")),
                   new JProperty("startValue",          StartValue),
                   new JProperty("keyId",               KeyId),
                   Identification is not null
                       ? new JProperty("identification",      Identification)
                       : new JProperty("identification",      JValue.CreateNull()),
                   IdentificationType is not null
                       ? new JProperty("identificationType",  IdentificationType)
                       : new JProperty("identificationType",  JValue.CreateNull())
               );

        /// <summary>
        /// A session read back from disk, or null when the file says nothing
        /// usable.
        /// </summary>
        internal static ChargingSession? TryParse(JObject JSON)
        {

            var id          = JSON["id"]?.        Value<String>();
            var keyId       = JSON["keyId"]?.     Value<String>();
            var startValue  = JSON["startValue"]?.Value<Decimal>();

            if (id is null || keyId is null || startValue is null)
                return null;

            if (!MeterJSON.TryReadMoment(JSON["startedAt"], out var startedAt))
                return null;

            return new ChargingSession(
                       id,
                       startedAt,
                       startValue.Value,
                       keyId,
                       JSON["identification"]?.    Type == JTokenType.String ? JSON["identification"]!.    Value<String>() : null,
                       JSON["identificationType"]?.Type == JTokenType.String ? JSON["identificationType"]!.Value<String>() : null
                   );

        }

        #endregion

        #region ToJSON()

        public JObject ToJSON()

            => new (
                   new JProperty("sessionId",   Id),
                   new JProperty("startedAt",   StartedAt.UtcDateTime.ToString("o")),
                   new JProperty("startValue",  StartValue),
                   new JProperty("unit",        "kWh"),
                   new JProperty("keyId",       KeyId),
                   Identification is not null
                       ? new JProperty("identification", Identification)
                       : new JProperty("identification", JValue.CreateNull())
               );

        #endregion

    }


    /// <summary>
    /// The charging sessions of this meter, and the counters OCMF documents are
    /// numbered with.
    /// </summary>
    /// <remarks>
    /// One session at a time, because this meter is one measuring point: a
    /// second session started while the first is running would have to share
    /// the same energy counter with it, and neither document would then mean
    /// what it says.
    ///
    /// The counters are on disk and not in memory. OCMF numbers every document
    /// a meter signs, and the point of the number is that a gap in it is
    /// visible - which it stops being the moment a restart sets the count back
    /// to one.
    /// </remarks>
    public class ChargingSessions
    {

        #region Data

        private readonly Lock    countersLock = new();
        private readonly String  countersPath;
        private readonly String  sessionPath;

        private UInt64           transactions;
        private UInt64           fiscals;

        #endregion

        #region Properties

        /// <summary>The directory the counters live in.</summary>
        public String            Path          { get; }

        /// <summary>Where this reads the time.</summary>
        public TimeProvider      TimeProvider  { get; }

        /// <summary>The session that is running, or null when none is.</summary>
        public ChargingSession?  Current       { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Open, or create, the session bookkeeping of a meter.
        /// </summary>
        /// <param name="Path">The directory it lives in.</param>
        /// <param name="TimeProvider">Where it reads the time.</param>
        public ChargingSessions(String         Path,
                                TimeProvider?  TimeProvider   = null)
        {

            this.Path          = System.IO.Path.GetFullPath(Path);
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;
            this.countersPath  = System.IO.Path.Combine(this.Path, "counters.json");
            this.sessionPath   = System.IO.Path.Combine(this.Path, "session.json");

            Directory.CreateDirectory(this.Path);

            try
            {

                if (File.Exists(countersPath))
                {
                    var json      = MeterJSON.ReadFile(countersPath);
                    transactions  = json["transactions"]?.Value<UInt64>() ?? 0;
                    fiscals       = json["fiscals"]?.     Value<UInt64>() ?? 0;
                }

            }
            catch
            {
                // Unreadable counters start again from zero rather than stopping
                // the meter. The gap that leaves is exactly what a gap in an
                // OCMF pagination counter is for.
            }

            // A session that was running when this meter last stopped. It is
            // still running: nothing about a charging session ends because the
            // software measuring it was restarted, and a car left plugged in
            // over a restart is the ordinary case rather than the strange one.
            try
            {

                if (File.Exists(sessionPath))
                    Current = ChargingSession.TryParse(MeterJSON.ReadFile(sessionPath));

            }
            catch
            {
                // An unreadable session file leaves no session running, which is
                // the safe direction: nothing gets signed on a start reading
                // nobody can vouch for.
            }

        }

        #endregion


        #region NextTransaction() / NextFiscal()

        /// <summary>
        /// The number of the next charging session document, OCMF "T".
        /// </summary>
        public UInt64 NextTransaction()
        {
            lock (countersLock)
            {
                transactions++;
                WriteCounters();
                return transactions;
            }
        }

        /// <summary>
        /// The number of the next reading this meter took on its own, OCMF "F".
        /// </summary>
        /// <remarks>
        /// A separate sequence from the sessions, as OCMF prescribes: a gap in
        /// one is not a gap in the other.
        /// </remarks>
        public UInt64 NextFiscal()
        {
            lock (countersLock)
            {
                fiscals++;
                WriteCounters();
                return fiscals;
            }
        }

        #endregion

        #region TryStart(...) / TryStop(out Session, out Error)

        /// <summary>
        /// Begin a charging session at the given reading.
        /// </summary>
        public Boolean TryStart(Decimal                            StartValue,
                                String                             KeyId,
                                String?                            Identification,
                                String?                            IdentificationType,
                                [NotNullWhen(true)]  out ChargingSession?  Session,
                                [NotNullWhen(false)] out String?          Error)
        {

            lock (countersLock)
            {

                if (Current is not null)
                {
                    Session = null;
                    Error   = $"A charging session is already running here since " +
                              $"{Current.StartedAt.UtcDateTime:yyyy-MM-dd HH:mm:ss}Z ('{Current.Id}'). " +
                               "This meter is one measuring point, so it can only be in one session at a time - stop that one first.";
                    return false;
                }

                var now = TimeProvider.GetUtcNow();

                Current = new ChargingSession(
                              $"{now:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}",
                              now,
                              StartValue,
                              KeyId,
                              Identification,
                              IdentificationType
                          );

                WriteSession();

                Session = Current;
                Error   = null;
                return true;

            }

        }

        /// <summary>
        /// End the session that is running, and hand it over.
        /// </summary>
        public Boolean TryStop([NotNullWhen(true)]  out ChargingSession?  Session,
                               [NotNullWhen(false)] out String?           Error)
        {

            lock (countersLock)
            {

                if (Current is null)
                {
                    Session = null;
                    Error   = "No charging session is running here, so there is nothing to stop.";
                    return false;
                }

                Session  = Current;
                Current  = null;

                WriteSession();

                Error    = null;
                return true;

            }

        }

        #endregion

        #region (private) WriteSession()

        /// <summary>
        /// Write down the session that is running, or take the file away when
        /// none is.
        /// </summary>
        /// <remarks>
        /// Written beside and moved into place, so that a process dying
        /// mid-write leaves the previous file rather than half of a new one -
        /// half a session file is a session nobody can stop.
        /// </remarks>
        private void WriteSession()
        {

            try
            {

                if (Current is null)
                {
                    if (File.Exists(sessionPath))
                        File.Delete(sessionPath);
                    return;
                }

                var temporary = sessionPath + ".new";

                File.WriteAllText(temporary, Current.StoredJSON().ToString());
                File.Move(temporary, sessionPath, overwrite: true);

            }
            catch
            {
                // A session that could not be written down is one a restart
                // would lose. Worth nothing stopping for, and the meter goes on
                // measuring it either way.
            }

        }

        #endregion

        #region (private) WriteCounters()

        private void WriteCounters()
        {

            try
            {
                File.WriteAllText(
                    countersPath,
                    new JObject(
                        new JProperty("transactions",  transactions),
                        new JProperty("fiscals",       fiscals)
                    ).ToString()
                );
            }
            catch
            {
                // A counter that could not be written is a counter that will
                // repeat itself after a restart. Worth nothing stopping for, and
                // visible in the documents when it happens.
            }

        }

        #endregion

    }

}
