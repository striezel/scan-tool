/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -------------------------------------------------------------------------------
*/

#ifndef CACHEMANAGERVIRUSTOTALV2_HPP
#define CACHEMANAGERVIRUSTOTALV2_HPP

#include <cstdint>
#include <string>

/** CacheManagerVirusTotalV2 can be used to manage the local request cache for
    VirusTotal API V2 reports. */
class CacheManagerVirusTotalV2
{
  public:
    /** \brief default constructor
     *
     * \param cacheRoot  path to the root directory of the cache;
     *                   an empty string will result in the default path for
     *                   the cache directory
     */
    CacheManagerVirusTotalV2(const std::string& cacheRoot = "");


    /** \brief gets the path of the default cache directory
     *
     * \return Returns the path to the default cache directory.
     * \remarks The directory does not necessarily need to exist.
     */
    static std::string getDefaultCacheDirectory();


    /** \brief gets the path of the current cache directory
     *
     * \return Returns the path to the current cache directory.
     * \remarks The directory does not necessarily need to exist.
     *          Use createCacheDirectory() to create it.
     */
    const std::string& getCacheDirectory() const;


    /** \brief Tries to create the cache directory, if it does not exist yet.
     *
     * \return Returns true, if the cache directory was created or already
     *         existed before the function was called.
     *         Returns false, if the cache directory could not be created.
     */
    bool createCacheDirectory();


    /** \brief Gets the hypothetical path for a cached element.
     *
     * \param resourceID  the resource ID, i.e. a SHA256 hash
     * \return Returns the full path to the file for the cached element.
     * Returns an empty string, if @resourceID is an invalid resource ID.
     * \remarks The function just returns a file path. It does not check, if
     *          the corresponding file exists. Therefore you cannot make any
     *          assumptions about the existence of the file.
     */
    std::string getPathForCachedElement(const std::string& resourceID) const;


    /** \brief Gets the hypothetical path for a cached element,
     *         using a custom cache root directory.
     *
     * \param resourceID  the resource ID, i.e. a SHA256 hash
     * \param cacheRoot   the cache's root directory
     * \return Returns the full path to the file for the cached element.
     * Returns an empty string, if @resourceID is an invalid resource ID.
     * \remarks The function just returns a file path. It does not check, if
     *          the corresponding file exists. Therefore you cannot make any
     *          assumptions about the existence of the file.
     */
    static std::string getPathForCachedElement(const std::string& resourceID, const std::string& cacheRoot);


    /** \brief tries to delete the cached element for a given resource ID
     *
     * \param resourceID  the resource ID, i.e. a SHA256 hash
     * \return Returns true, if the cached resource was deleted or did not
     *         exist at the time of the function call.
     *         Returns false, if the cached element could not be deleted and
     *         is still there or if @resourceID is an invalid resource ID.
     */
    bool deleteCachedElement(const std::string& resourceID);


    /** \brief tries to delete the cached element for a given resource ID,
     *         using a custom cache root directory
     *
     * \param resourceID  the resource ID, i.e. a SHA256 hash
     * \param cacheRoot   the cache's root directory
     * \return Returns true, if the cached resource was deleted or did not
     *         exist at the time of the function call.
     *         Returns false, if the cached element could not be deleted and
     *         is still there or if @resourceID is an invalid resource ID.
     */
    static bool deleteCachedElement(const std::string& resourceID, const std::string& cacheRoot);


     /** \brief checks all present cache files for integrity
      *
      * \param deleteCorrupted  If set to true, corrupted cache files will be deleted.
      * \param deleteUnknown    If set to true, all reports of resources that are not
      *                         known to VT will be deleted. These reports do not count
      *                         as corrupted and do not influence the return value.
      * \return Returns the number of corrupted files that were found.
      *         Returns zero, if no corrupted files were found.
      */
    uint_least32_t checkIntegrity(const bool deleteCorrupted, const bool deleteUnknown) const;


    /** \brief moves cached files from the old cache directory structure
     *         without subdirectories to their new location in the current
     *         directory structure with 256 subdirectories
     *
     * \return Returns the number of files that were moved.
     * \remarks The request cache without subdirectories was used in versions
     *          0.20 and 0.21 of scan-tool.
     *          In order to perform the transition the new directories must
     *          already be present. Call createCacheDirectory() to achieve that.
     */
    uint_least32_t transitionOneTo256();


    /** \brief moves cached files from the old cache directory structure with
     *         16 subdirectories to their new location in the current directory
     *         structure with 256 subdirectories
     *
     * \return Returns the number of files that were moved.
     * \remarks The request cache with 16 subdirectories was used in versions
     *          0.22 till 0.25 of scan-tool.
     *          In order to perform the transition the new directories must
     *          already be present. Call createCacheDirectory() to achieve that.
     */
    uint_least32_t transition16To256();
  private:
    std::string m_CacheRoot; /**< path to the chosen root cache directory */
}; //class

#endif // CACHEMANAGERVIRUSTOTALV2_HPP
