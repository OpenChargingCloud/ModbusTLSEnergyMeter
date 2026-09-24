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

using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The lines a clock check writes into the log read the same on every
    /// machine.
    /// </summary>
    /// <remarks>
    /// The sentences are English and end up in a log that is kept as a record
    /// of what the clock was doing. Under a German culture their numbers used
    /// to be written with a decimal comma - "+2,5 ms from 3 server(s), spread
    /// 2,0 ms" - so that the punctuation of a record changed with the machine
    /// that wrote it. And the agreed deviation was written in whole seconds,
    /// while it may be set as low as a millisecond: 0.001 s read "0 s".
    /// </remarks>
    public class NTSLogLineTests
    {

        #region Data

        private static readonly TimeSpan  oneMillisecond  = TimeSpan.FromMilliseconds(1);

        #endregion

        #region (private static) Answer(Name, OffsetMilliseconds)

        /// <summary>
        /// A server that answered, authenticated, with the given offset.
        /// </summary>
        private static NTSMeasurementResult Answer(String  Name,
                                                   Double  OffsetMilliseconds)

            => new (DomainName.Parse(Name),
                    Guid.Empty) {

                   Success  = true,
                   NTP      = new NTPMeasurementResult {
                                  Success                 = true,
                                  NTSAuthenticationValid  = true,
                                  Offset                  = TimeSpan.FromMilliseconds(OffsetMilliseconds)
                              }

               };

        #endregion

        #region (private static) ThreeThatDisagree(out Verdict)

        /// <summary>
        /// Three servers, 1.5, 2.5 and 3.5 ms off, held to two of them and to a
        /// deviation of a millisecond: a time of +2.5 ms, and a spread of two
        /// milliseconds that reaches the agreed deviation.
        /// </summary>
        private static TimeSourceGroup ThreeThatDisagree(out TimeSyncVerdict Verdict)
        {

            var group = new TimeSourceGroup(
                            "legal",
                            [
                                new NTSServerEndpoint(DomainName.Parse("a.example")),
                                new NTSServerEndpoint(DomainName.Parse("b.example")),
                                new NTSServerEndpoint(DomainName.Parse("c.example"))
                            ],
                            MinServers:    2,
                            MaxDeviation:  oneMillisecond
                        );

            Verdict = TimeSyncVerdict.From(
                          [ Answer("a.example", 1.5), Answer("b.example", 2.5), Answer("c.example", 3.5) ],
                          group.MinServers,
                          group.MaxDeviation
                      );

            return group;

        }

        #endregion


        #region TheAnswerIsWrittenWithAPointUnderAGermanCulture()

        /// <summary>
        /// The line a clock check that found a time ends with: the half
        /// sentence Norn writes, which was the culture's until Norn 724d5fd.
        /// </summary>
        [Test]
        [SetCulture("de-DE")]
        public void TheAnswerIsWrittenWithAPointUnderAGermanCulture()
        {

            var group = ThreeThatDisagree(out var verdict);

            Assert.That(ModbusTLSEnergyMeter.AnsweredLine(group, 57, verdict),
                        Is.EqualTo("NTS: group 'legal' answered in 57 ms - +2.5 ms from 3 server(s), spread 2.0 ms - beyond the agreed deviation."));

        }

        #endregion

        #region TheDisagreementIsWrittenWithAPointAndItsDeviationInFull()

        /// <summary>
        /// The warning beside it, which is this meter's own sentence: the
        /// spread with a point, and the agreed deviation with as many places as
        /// it has.
        /// </summary>
        [Test]
        [SetCulture("de-DE")]
        public void TheDisagreementIsWrittenWithAPointAndItsDeviationInFull()
        {

            var group = ThreeThatDisagree(out var verdict);

            Assert.That(ModbusTLSEnergyMeter.DisagreementLine(group, verdict),
                        Is.EqualTo("NTS: the time servers of group 'legal' disagree by 2.0 ms, which reaches the agreed deviation of 0.001 s."));

        }

        #endregion

    }

}
