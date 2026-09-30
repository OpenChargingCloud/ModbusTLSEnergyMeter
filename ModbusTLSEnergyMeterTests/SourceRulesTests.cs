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

using cloud.charging.open.protocols.WWCP.Node.TestKit;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What the meter's own C# says, held to the rules of WWCP_Node_TestKit's
    /// SourceRules - as its pages are held to the rules of the node's
    /// Frontend/test/pages.ts.
    /// </summary>
    public class SourceRulesTests
    {

        #region NoArticleBeforeAName()

        /// <summary>
        /// No "a" or "an" in front of a name that is interpolated, neither in the
        /// meter's code nor in its tests: which article a name takes goes by how
        /// the name is said, which the text cannot know - the kit's own "A
        /// {Node.Kind.Name}" read "A energy meter" (found by the EV). A name is
        /// said with its article, as CertificateKind.WithArticle() says it, or
        /// without one: "this energy meter".
        /// </summary>
        [Test]
        public void NoArticleBeforeAName()
        {

            var repository = SourceRules.RepositoryAbove(AppContext.BaseDirectory, "ModbusTLSEnergyMeter", "ModbusTLSEnergyMeterTests");

            Assert.That(SourceRules.ArticlesBeforeANameIn(Path.Combine(repository, "ModbusTLSEnergyMeter"),
                                                          Path.Combine(repository, "ModbusTLSEnergyMeterTests")),
                        Is.Empty);

        }

        #endregion

    }

}
