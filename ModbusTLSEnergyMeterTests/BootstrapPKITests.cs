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

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

using static cloud.charging.open.protocols.WWCP.Node.TestKit.OwnerOnlyChecks;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The PKI a meter builds at its first start holds the private keys of its
    /// CAs and of a client of every role: whoever may read them may issue
    /// themselves any role. It is its owner's alone, like everything else the
    /// meter keeps.
    /// </summary>
    public class BootstrapPKITests
    {

        #region Data

        private String directory = default!;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {
            directory = Path.Combine(Path.GetTempPath(), "meter-pki-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);
        }

        [TearDown]
        public void TearDown()
        {
            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            { }
        }

        #endregion


        #region APKIJustBuiltIsItsOwnersAlone()

        /// <summary>
        /// Built by Hermod's ModbusPKI and taken in: nobody else gets into the
        /// directory, nor into any file of it - the CA's key and server.pfx
        /// among them - and the owner still reads all of them.
        /// </summary>
        [Test]
        public async Task APKIJustBuiltIsItsOwnersAlone()
        {

            var pki = Path.Combine(directory, "pki");

            await new ModbusPKI().BuildPKI(pki);

            BootstrapPKI.KeepToItsOwner(pki, problem => Assert.Fail(problem));

            var files = Directory.EnumerateFiles(pki).ToArray();

            Assert.Multiple(() => {

                Assert.That(OthersMayGetIn(pki), Is.Empty);
                Assert.That(files.Select(Path.GetFileName), Does.Contain("ca.key").And.Contain("server.pfx").And.Contain("ca.crt"));

                foreach (var file in files)
                {
                    Assert.That(OthersMayGetIn(file),     Is.Empty,     Path.GetFileName(file));
                    Assert.That(File.ReadAllBytes(file),  Is.Not.Empty, $"{Path.GetFileName(file)}, read by its owner");
                }

            });

        }

        #endregion

        #region APKIAnOlderVersionLeftOpenIsTakenBack()

        /// <summary>
        /// A PKI built before this, in a directory everybody may read, its CA's
        /// key opened to everybody besides: its owner's alone afterwards.
        /// </summary>
        [Test]
        public async Task APKIAnOlderVersionLeftOpenIsTakenBack()
        {

            var pki = Path.Combine(directory, "pki");

            OpenToEverybody(pki);
            await new ModbusPKI().BuildPKI(pki);

            var key = Path.Combine(pki, "ca.key");

            OpenToEverybody(key);

            Assume.That(OthersMayGetIn(pki), Is.Not.Empty);
            Assume.That(OthersMayGetIn(key), Is.Not.Empty);

            BootstrapPKI.KeepToItsOwner(pki, problem => Assert.Fail(problem));

            Assert.Multiple(() => {
                Assert.That(OthersMayGetIn(pki), Is.Empty);
                Assert.That(OthersMayGetIn(key), Is.Empty);
            });

        }

        #endregion

        #region NoDirectoryNothingMade()

        /// <summary>
        /// A PKI directory that is not there - certificates given from
        /// elsewhere - is not made.
        /// </summary>
        [Test]
        public void NoDirectoryNothingMade()
        {

            var pki = Path.Combine(directory, "not-there");

            BootstrapPKI.KeepToItsOwner(pki, problem => Assert.Fail(problem));

            Assert.That(Directory.Exists(pki), Is.False);

        }

        #endregion

    }

}
