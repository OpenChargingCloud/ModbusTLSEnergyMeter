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

using System.Security.Cryptography;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// A directory of the meter's that is one thing - a signing key, a signing
    /// request, each a private key with what belongs to it - taken away in one
    /// step or not at all.
    /// </summary>
    /// <remarks>
    /// Deleted file by file, such a directory was left half when somebody else
    /// held one of its files open - a virus scanner, a backup, an editor: a
    /// signing key's meta.json went and its private.key stayed, while the meter
    /// answered that the key could not be removed, and the next start knew the
    /// key no longer - and nothing named the private key left on disk. The
    /// local controller closed the same gap in its stores of keys and chains
    /// (LocalController e6d61d3, found by the charging station).
    /// </remarks>
    internal static class DirectoryRemoval
    {

        /// <summary>
        /// What the name of a directory set aside to be deleted ends with. No
        /// store reads a directory whose name ends so.
        /// </summary>
        internal const String SetAsideSuffix = ".removed";

        /// <summary>
        /// Whether the given directory is one set aside to be deleted.
        /// </summary>
        /// <param name="Directory">A directory of a store.</param>
        internal static Boolean IsSetAside(String Directory)

            => Directory.TrimEnd('/', '\\').EndsWith(SetAsideSuffix, StringComparison.Ordinal);

        /// <summary>
        /// Take a directory away: renamed first, in one step, and only then
        /// deleted.
        /// </summary>
        /// <remarks>
        /// On Windows the rename fails as long as a file in the directory is
        /// open, and then nothing has changed - the exception says why. Once it
        /// is renamed, what is left of it is read by nobody, even where deleting
        /// it fails afterwards: then it is only said where it was left.
        /// </remarks>
        /// <param name="Directory">The directory to take away.</param>
        /// <param name="BeforeSettingAside">What happens before it is set aside - for the tests, where throwing is the rename that fails.</param>
        /// <param name="BeforeDeleting">What happens once it is set aside and before it is deleted - for the tests.</param>
        /// <returns>Where what could not be deleted was left, or null when all of it is gone.</returns>
        internal static String? RemoveInOneStep(String           Directory,
                                                Action<String>?  BeforeSettingAside   = null,
                                                Action<String>?  BeforeDeleting       = null)
        {

            var aside = $"{Directory.TrimEnd('/', '\\')}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant()}{SetAsideSuffix}";

            BeforeSettingAside?.Invoke(Directory);

            System.IO.Directory.Move(Directory, aside);

            try
            {
                BeforeDeleting?.Invoke(aside);
                System.IO.Directory.Delete(aside, recursive: true);
                return null;
            }
            catch (Exception)
            {
                return aside;
            }

        }

    }

}
